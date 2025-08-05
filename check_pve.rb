#!/usr/bin/env ruby
# frozen_string_literal: true

#
# PVE Plugin
# ==
# Author: Marco Peterseil
# Created: 12-2017
# License: GPLv3 - http://www.gnu.org/licenses
# URL: https://gitlab.com/6uellerBpanda/check_pve
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

require 'optparse'
require 'net/https'
require 'json'
require 'date'
require 'time'

version = 'v0.3.0'

# optparser
banner = <<~HEREDOC
  check_pve #{version} [https://gitlab.com/6uellerBpanda/check_pve]\n
  This plugin checks various parameters of Proxmox Virtual Environment via API(v2)\n
  Mode:
    Cluster:
      cluster-status            Checks quorum of cluster
    Node:
      node-smart-status          Checks SMART health of disks
      node-updates-available     Checks for available updates
      node-subscription-valid    Checks for valid subscription
      node-services-status       Checks if services are running
      node-task-errors           Checks for task errors
      node-storage-usage         Checks storage usage in percentage
      node-storage-status        Checks if storage is online/offline
      node-cpu-usage             Checks CPU usage in percentage
      node-memory-usage          Checks Memory usage in gigabytes
      node-io-wait               Checks IO wait in percentage
      node-net-in-usage          Checks inbound network usage in kilobytes
      node-net-out-usage         Checks outbound network usage in kilobytes
      node-ksm-usage             Checks KSM sharing usage in megabytes
    VM:
      vm-cpu-usage               Checks CPU usage in percentage
      vm-memory-usage            Checks memory usage
      vm-disk-read-usage         Checks how many kb last 60s was read (timeframe: hour)
      vm-disk-write-usage        Checks how many kb last 60s was written (timeframe: hour)
      vm-net-in-usage            Checks incoming kb from last 60s (timeframe: hour)
      vm-net-out-usage           Checks outgoing kb from last 60s (timeframe: hour)

  Usage: #{File.basename(__FILE__)} [mode] [options]
HEREDOC

options = { unit: 'mb', timeframe: 'hour', cf: 'max' }
OptionParser.new do |opts| # rubocop:disable  Metrics/BlockLength
  opts.banner = banner.to_s
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-s', '--address ADDRESS', '-H', 'PVE host address') do |s|
    options[:address] = s
  end
  opts.on('-k', '--insecure', 'No SSL verification') do |k|
    options[:insecure] = k
  end
  opts.on('-m', '--mode MODE', 'Mode to check') do |m|
    options[:mode] = m
  end
  opts.on('-n', '--node NODE', 'PVE Node name') do |n|
    options[:node] = n
  end
  opts.on('-u', '--username USERNAME', 'Username with auth realm e.g. monitoring@pve') do |u|
    options[:username] = u
  end
  opts.on('-p', '--password PASSWORD', 'Password') do |p|
    options[:password] = p
  end
  opts.on('-w', '--warning WARNING', 'Warning threshold') do |w|
    options[:warning] = w
  end
  opts.on('-c', '--critical CRITICAL', 'Critical threshold') do |c|
    options[:critical] = c
  end
  opts.on('--unit UNIT', %i[kb mb gb tb], String, 'Unit - kb, mb, gb, tb') do |unit|
    options[:unit] = unit
  end
  opts.on('--name NAME', 'Name for storage or user filter for tasks') do |name|
    options[:name] = name
  end
  opts.on('-i', '--vmid VMID', 'ID of qemu/lxc machine') do |i|
    options[:vmid] = i
  end
  opts.on('-t', '--type TYPE', 'VM type lxc, qemu or type filter for tasks') do |t|
    options[:type] = t
  end
  opts.on('-x', '--exclude EXCLUDE', 'Exclude (regex)') do |x|
    options[:exclude] = x
  end
  opts.on('--timeframe TIMEFRAME', 'Timeframe for vm checks: hour,day,week,month or year. Default hour') do |timeframe|
    options[:timeframe] = timeframe
  end
  opts.on('--cf CONSOLIDATION_FUNCTION', 'RRD cf: average or max. Default max') do |cf|
    options[:cf] = cf
  end
  opts.on('--lookback LOOKBACK', Integer, 'Lookback in seconds') do |lookback|
    options[:lookback] = lookback
  end
  opts.on('-v', '--version', 'Print version information') do
    puts "check_pve #{version}"
  end
  opts.on('-h', '--help', 'Show this help message') do
    puts opts
  end
  ARGV.push('-h') if ARGV.empty?
end.parse!

# check pve
class CheckPve
  def initialize(options) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    @options = options
    init_arr
    cluster_status
    node_smart_status
    node_updates_available
    node_services_status
    node_subscription_valid
    node_cpu_usage
    node_memory_usage
    node_ksm_usage
    node_io_wait
    node_storage_usage
    node_storage_status
    node_task_errors
    node_net_in_usage
    node_net_out_usage
    vm_disk_write_usage
    vm_disk_read_usage
    vm_cpu_usage
    vm_memory_usage
    vm_net_in_usage
    vm_net_out_usage
  end

  def init_arr
    @perfdata = []
    @message = []
    @critical = []
    @warning = []
    @okays = []
  end

  #--------#
  # HELPER #
  #--------#

  # define some helper methods for naemon with appropriate exit codes
  def ok_msg(message)
    puts "OK - #{message}"
    exit 0
  end

  def crit_msg(message)
    puts "Critical - #{message}"
    exit 2
  end

  def warn_msg(message)
    puts "Warning - #{message}"
    exit 1
  end

  def unk_msg(message)
    puts "Unknown - #{message}"
    exit 3
  end

  def convert_value(type:, value1:, value2:) # rubocop:disable Metrics/AbcSize
    @usage = case type
             when '%' then value2.to_s.empty? ? format('%.2f', value1 * 100).to_f.round(2) : ((value1.to_f * 100) / value2).to_f.round(2)
             when 'kb' then (value1.to_f / 1024).round(2)
             when 'mb' then (value1.to_f / 1024 / 1024).round(2)
             when 'gb' then (value1.to_f / 1024 / 1024 / 1024).round(2)
             when 'tb' then (value1.to_f / 1024 / 1024 / 1024 / 1024).round(2)
             end
  end

  # check only one value
  def check_single_data(data:, message:)
    crit_msg(message) if data
  end

  def check_multiple_data(data:)
    if data
      warn_msg(@status_msg[:warn])
    else
      ok_msg(@status_msg[:ok])
    end
  end

  # helper for excluding
  def exclude(data:, value:)
    data.delete_if { |item| /#{@options[:exclude]}/.match(item[value]) } unless @options[:exclude].to_s.empty?
  end

  # generate perfdata
  def build_perfdata(perfdata:)
    @perfdata << "#{perfdata};#{@options[:warning]};#{@options[:critical]}"
  end

  # build service output
  def build_output(postfix_text: '', join_value: '', warn_text: '', ok_text: '', msg_type: 'plain')
    case msg_type
    when 'mapped'
      @status_msg = {
        warn: @filtered_json[:down].map { |item| item[join_value].to_s }.join(', ') << postfix_text[:down].to_s,
        ok: @filtered_json[:online].map { |item| item[join_value].to_s }.join(', ') << postfix_text[:online].to_s
      }
    when 'plain'
      @status_msg = { warn: warn_text, ok: ok_text }
    end
  end

  # helper for threshold checking
  def check_thresholds(data:)
    if data > @options[:critical].to_i
      @critical << @message
    elsif data > @options[:warning].to_i
      @warning << @message
    else
      @okays << @message
    end
    # make the final step
    build_final_output
  end

  # mix everything together for exit
  def build_final_output
    perf_output = " | #{@perfdata.join(' ')}"
    if @critical.any?
      crit_msg(@critical.join(', ') + perf_output)
    elsif @warning.any?
      warn_msg(@warning.join(', ') + perf_output)
    else
      ok_msg(@okays.join(', ') + perf_output)
    end
  end

  #----------#
  # API AUTH #
  #----------#

  def url(path:, req: 'get') # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    uri = URI("https://#{@options[:address]}:8006/#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @options[:insecure]
    if req == 'post'
      request = Net::HTTP::Post.new(uri.request_uri)
      request.set_form_data('username' => @options[:username].to_s, 'password' => @options[:password].to_s)
    else
      fetch_cookie
      request = Net::HTTP::Get.new(uri.request_uri)
      request['cookie'] = @token
    end
    @response = http.request(request)
  rescue StandardError => e
    unk_msg(e)
  end

  # check http response
  def check_http_response
    unk_msg(@response.message).to_s if @response.code != '200'
  end

  # init http req
  def http_connect(path:, req: 'get')
    url(path: path, req: req)
    check_http_response
    @json_body = JSON.parse(@response.body)['data']
  end

  # get cookie
  def fetch_cookie
    http_connect(path: 'api2/json/access/ticket', req: 'post')
    @token = "PVEAuthCookie=#{JSON.parse(@response.body)['data']['ticket']}"
  end

  #--------#
  # CHECKS #
  #--------#

  ###--- CLUSTER CHECK ---###
  def cluster_status
    return unless @options[:mode] == 'cluster-status'
    http_connect(path: 'api2/json/cluster/status')
    cluster = @json_body.first
    build_output(
      warn_text: "#{cluster['name'].upcase}: Cluster not ready - no quorum",
      ok_text: "#{cluster['name'].upcase}: Cluster ready - quorum is ok"
    )
    check_multiple_data(data: cluster['quorate'] != 1)
  end

  ###--- SMART CHECK ---###
  def node_smart_status
    return unless @options[:mode] == 'node-smart-status'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/disks/list")
    unhealthy = @json_body.reject { |item| item['health'] == 'PASSED' || 'OK' }
    exclude(data: unhealthy, value: 'devpath')
    build_output(
      warn_text: unhealthy.map { |item| "#{item['model']}:#{item['used']}-#{item['devpath']} SMART error detected" }.join(', '),
      ok_text: 'No SMART errors detected'
    )
    check_multiple_data(data: unhealthy.any?)
  end

  ###--- UPDATE CHECK ---###
  def node_updates_available
    return unless @options[:mode] == 'node-updates-available'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/apt/update")
    build_output(
      warn_text: "#{@json_body.count} updates available",
      ok_text: 'System up to date'
    )
    check_multiple_data(data: @json_body.any?)
  end

  ###--- SERVICES CHECK ---###
  def node_services_status # rubocop:disable Metrics/MethodLength
    return unless @options[:mode] == 'node-services-status'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/services")
    exclude(data: @json_body, value: 'name')
    @filtered_json = {
      online: @json_body.select { |item| item['state'] == 'running' },
      down: @json_body.reject { |item| item['state'] == 'running' }
    }
    build_output(
      msg_type: 'mapped',
      join_value: 'name',
      postfix_text: { online: ' started', down: ' stopped' }
    )
    check_multiple_data(data: @filtered_json[:down].any?)
  end

  ###--- SUBSCRIPTION CHECK ---###
  def node_subscription_valid
    return unless @options[:mode] == 'node-subscription-valid'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/subscription")
    due_date = @json_body['nextduedate']
    check_single_data(data: @json_body['status'] != 'Active', message: @json_body['message'])
    build_output(
      warn_text: "Subscription will end at #{due_date}",
      ok_text: "Subscription is valid till #{due_date}"
    )
    check_multiple_data(data: Date.parse(due_date) < Date.today + @options[:warning].to_i)
  end

  ###--- TASK CHECK ---###
  def node_task_errors # rubocop:disable Metrics/AbcSize
    return unless @options[:mode] == 'node-task-errors'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/tasks?errors=1&typefilter=#{@options[:type]}&userfilter=#{@options[:name]}")
    exclude(data: @json_body, value: 'status')
    @json_body.delete_if { |item| item['starttime'].to_i < (Time.now.round.to_i - @options[:lookback]) }
    build_output(
      warn_text: @json_body.map { |item| "#{Time.at(item['starttime'])}: #{item['type']}/#{item['user']} - #{item['status']}" }.join(', '),
      ok_text: 'No failed tasks'
    )
    check_multiple_data(data: @json_body.any?)
  end

  ###--- NODE CHECKS ---###
  def fetch_status_data(type: 'node', path: 'status')
    check_rrddata_path
    type == 'node' ? http_connect(path: "api2/json/nodes/#{@options[:node]}/#{path}") : http_connect(path: "api2/json/nodes/#{@rrddata_path}/rrddata?timeframe=#{@options[:timeframe]}&cf=#{@options[:cf].upcase}") # rubocop:disable Layout/LineLength
  end

  # helper for vm node checks
  def node_vm_helper(output_msg:, value:, perf_label: 'Usage', convert_value_to: @options[:unit], value_to_compare: '')
    convert_value(type: convert_value_to, value1: value, value2: value_to_compare)
    @message = "#{output_msg}: #{@usage}#{convert_value_to.upcase}"
    build_perfdata(perfdata: "#{perf_label}=#{@usage}#{convert_value_to.upcase}")
    check_thresholds(data: @usage)
  end

  # helper for rrddata
  def check_rrddata_path
    @options[:vmid] ? @rrddata_path = "#{@options[:node]}/#{@options[:type]}/#{@options[:vmid]}" : @rrddata_path = @options[:node] # rubocop:disable Style/ConditionalAssignment
  end

  ### node: cpu
  def node_cpu_usage
    return unless @options[:mode] == 'node-cpu-usage'
    fetch_status_data
    node_vm_helper(value: @json_body['cpu'], output_msg: 'CPU usage', convert_value_to: '%')
  end

  ### node: io wait
  def node_io_wait
    return unless @options[:mode] == 'node-io-wait'
    fetch_status_data
    node_vm_helper(value: @json_body['wait'], output_msg: 'IO Wait', perf_label: 'Wait')
  end

  ### node: memory
  def node_memory_usage
    return unless @options[:mode] == 'node-memory-usage'
    fetch_status_data
    node_vm_helper(value: @json_body['memory']['used'], output_msg: 'Memory usage', value_to_compare: @json_body['memory']['total'], convert_value_to: '%')
  end

  ### node: ksm
  def node_ksm_usage
    return unless @options[:mode] == 'node-ksm-usage'
    fetch_status_data
    node_vm_helper(value: @json_body['ksm']['shared'], output_msg: 'KSM sharing')
  end

  ### node: storage usage
  def node_storage_usage
    return unless @options[:mode] == 'node-storage-usage'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/storage/#{@options[:name]}/status")
    node_vm_helper(
      value: @json_body['used'],
      value_to_compare: @json_body['total'],
      output_msg: 'Storage usage',
      convert_value_to: '%'
    )
  end

  ### node: storage status
  def node_storage_status # rubocop:disable Metrics/MethodLength
    return unless @options[:mode] == 'node-storage-status'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/storage")
    exclude(data: @json_body, value: 'storage')
    @filtered_json = {
      online: @json_body.select { |item| item['active'] == 1 && item['enabled'] == 1 },
      down: @json_body.select { |item| item['active'].zero? && item['enabled'] == 1 }
    }
    build_output(
      msg_type: 'mapped',
      join_value: 'storage',
      postfix_text: { online: ' are active', down: 'not active' }
    )
    check_multiple_data(data: @filtered_json[:down].any?)
  end

  ### node: netin
  def node_net_in_usage
    return unless @options[:mode] == 'node-net-in-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['netin'], output_msg: 'Network usage in')
  end

  ### node: netout
  def node_net_out_usage
    return unless @options[:mode] == 'node-net-out-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['netout'], output_msg: 'Network usage out')
  end

  ###--- QEMU, LXC CHECKS ---###
  # disk
  def vm_disk_write_usage
    return unless @options[:mode] == 'vm-disk-write-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['diskwrite'], output_msg: 'Disk write')
  end

  def vm_disk_read_usage
    return unless @options[:mode] == 'vm-disk-read-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['diskread'], output_msg: 'Disk read')
  end

  # cpu
  def vm_cpu_usage
    return unless @options[:mode] == 'vm-cpu-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['cpu'], output_msg: 'CPU usage', convert_value_to: '%')
  end

  # memory
  def vm_memory_usage
    return unless @options[:mode] == 'vm-memory-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['mem'], output_msg: 'Memory usage', value_to_compare: @json_body[-1]['maxmem'], convert_value_to: '%')
  end

  # network
  def vm_net_in_usage
    return unless @options[:mode] == 'vm-net-in-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['netin'], output_msg: 'Network usage in')
  end

  def vm_net_out_usage
    return unless @options[:mode] == 'vm-net-out-usage'
    fetch_status_data(type: 'rrd')
    node_vm_helper(value: @json_body[-1]['netout'], output_msg: 'Network usage out')
  end
end

CheckPve.new(options)
