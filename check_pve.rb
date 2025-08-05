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

# Constants
NAGIOS_EXIT_CODES = {
  ok: 0,
  warning: 1,
  critical: 2,
  unknown: 3
}.freeze

BYTE_UNITS = {
  'kb' => 1024,
  'mb' => 1024**2,
  'gb' => 1024**3,
  'tb' => 1024**4,
  'pb' => 1024**5
}.freeze

VERSION = 'v0.5.6'

# optparser
banner = <<HEREDOC
  check_pve #{VERSION} [https://gitlab.com/6uellerBpanda/check_pve]\n
  This plugin checks various parameters of Proxmox Virtual Environment via API(v2)\n
  Mode:
    Cluster:
      cluster-status             Checks quorum of cluster
    Node:
      node-smart-status          Checks SMART health of disks
      node-updates-available     Checks for available updates
      node-subscription-valid    Checks for valid subscription
      node-services-status       Checks if services are running
      node-task-errors           Checks for task errors
      node-storage-usage         Checks storage usage in percentage
      node-storage-status        Checks if storage is online/offline
      node-cpu-usage             Checks CPU usage in percentage
      node-cpu-load              Checks CPU load average
      node-memory-usage          Checks Memory usage in gigabytes
      node-io-wait               Checks IO wait in percentage
      node-net-in-usage          Checks inbound network usage in kilobytes
      node-net-out-usage         Checks outbound network usage in kilobytes
      node-ksm-usage             Checks KSM sharing usage in megabytes
    VM:
      vm-status                  Checks the status of a vm (running = OK)
      vm-cpu-usage               Checks CPU usage in percentage
      vm-memory-usage            Checks memory usage
      vm-disk-read-usage         Checks how many kb last 60s was read (timeframe: hour)
      vm-disk-write-usage        Checks how many kb last 60s was written (timeframe: hour)
      vm-net-in-usage            Checks incoming kb from last 60s (timeframe: hour)
      vm-net-out-usage           Checks outgoing kb from last 60s (timeframe: hour)
    Misc:
      list-nodes                 Lists all PVE nodes
      list-vms                   Lists all VMs across all nodes

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
  opts.on('--unit UNIT', %i[kb mb gb tb pb], String, 'Unit - kb, mb, gb, tb, pb') do |unit|
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
  opts.on('-r', '--percpu', 'Divide the load averages by the number of CPUs (when possible)') do |percpu|
    options[:percpu] = percpu
  end
  opts.on('--timeframe TIMEFRAME', 'Timeframe for vm checks: hour,day,week,month or year. Default: hour') do |timeframe|
    options[:timeframe] = timeframe
  end
  opts.on('--cf CONSOLIDATION_FUNCTION', 'RRD cf: average or max. Default: max') do |cf|
    options[:cf] = cf
  end
  opts.on('--lookback LOOKBACK', Integer, 'Lookback in seconds') do |lookback|
    options[:lookback] = lookback
  end
  opts.on('-d', '--debug', 'Enable debug') do |d|
    options[:debug] = d
  end
  opts.on('-v', '--version', 'Print version information') do
    puts "check_pve #{VERSION}"
  end
  opts.on('-h', '--help', 'Show this help message') do
    puts opts
    exit 0
  end
  ARGV.push('-h') if ARGV.empty?
end.parse!


cluster_modes = %w[
  cluster-status
]

node_modes = %w[
  node-smart-status
  node-updates-available
  node-subscription-valid
  node-services-status
  node-task-errors
  node-storage-usage
  node-storage-status
  node-cpu-usage
  node-cpu-load
  node-memory-usage
  node-io-wait
  node-net-in-usage
  node-net-out-usage
  node-ksm-usage
]

vm_modes = %w[
  vm-status
  vm-cpu-usage
  vm-memory-usage
  vm-disk-read-usage
  vm-disk-write-usage
  vm-net-in-usage
  vm-net-out-usage
]

misc_modes = %w[
  list-nodes
  list-vms
]

all_modes = cluster_modes + node_modes + vm_modes + misc_modes

if options[:address].nil? || options[:address].empty?
  warn ""
  warn "ERROR: Option --address is required"
  exit 20
end

if options[:username].nil? || options[:username].empty?
  warn ""
  warn "ERROR: Option --username is required"
  exit 21
end

if options[:password].nil? || options[:password].empty?
  warn ""
  warn "ERROR: Option --password is required"
  exit 22
end

if options[:mode].nil? || options[:mode].empty?
  warn ""
  warn 'ERROR: Option --mode is required'
  exit 23
elsif !all_modes.include?(options[:mode])
  warn ""
  warn "ERROR: Invalid --mode: '#{options[:mode]}'"
  warn ""
  warn "Valid values are:"
  warn "  Cluster: #{cluster_modes.join(', ')}"
  warn "  Node:    #{node_modes.join(', ')}"
  warn "  VM:      #{vm_modes.join(', ')}"
  warn "  Misc:    #{misc_modes.join(', ')}"
  exit 24
end

if vm_modes.include?(options[:mode]) && options[:vmid].nil?
  warn ""
  warn "ERROR: Option --vmid is required for mode '#{options[:mode]}'"
  exit 25
end


# check pve
class CheckPve
  def initialize(options) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    @options = options
    init_arr
    set_default_thresholds
    cluster_status
    node_smart_status
    node_updates_available
    node_services_status
    node_subscription_valid
    node_cpu_usage
    node_cpu_load
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
    vm_status
    vm_cpu_usage
    vm_memory_usage
    vm_net_in_usage
    vm_net_out_usage
    list_nodes
    list_vms
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

  # set default thresholds if no values are suppulied via args
  def set_default_thresholds()
    if @options[:mode] == 'node-cpu-load'
      @options[:warning]  ||= '2,1.5,0.9'
      @options[:critical] ||= '3,2,1'
    else
      @options[:warning]  ||= 80
      @options[:critical] ||= 90
    end
  end

  # define some helper methods for naemon with appropriate exit codes
  def ok_msg(message)
    puts "OK: #{message}"
    exit NAGIOS_EXIT_CODES[:ok]
  end

  def crit_msg(message)
    puts "CRITICAL: #{message}"
    exit NAGIOS_EXIT_CODES[:critical]
  end

  def warn_msg(message)
    puts "WARNING: #{message}"
    exit NAGIOS_EXIT_CODES[:warning]
  end

  def unk_msg(message)
    puts "UNKNOWN: #{message}"
    exit NAGIOS_EXIT_CODES[:unknown]
  end

  def convert_value(args = {})
    type = args[:type]
    value1 = args[:value1]
    value2 = args[:value2]

    unk_msg("value1 is nil in function #{__method__}") if value1.nil?
    unk_msg("value2 is nil in function #{__method__}") if value2.nil? && type == '%'

    @usage = case type
             when '%'
               if value2.to_s.empty?
                 (value1 * 100).to_f.round(2)
               else
                 ((value1.to_f * 100) / value2).to_f.round(2)
               end
             when *BYTE_UNITS.keys
               (value1.to_f / BYTE_UNITS[type]).round(2)
             else
               unk_msg("Unknown unit type: #{type}in function #{__method__}")
             end
  end

  # check only one value
  def check_single_data(args = {})
    data = args[:data]
    message = args[:message]
    crit_msg(message) if data
  end

  # check multiple values
  def check_multiple_data(args = {})
    multi      = args[:multi] || false
    data       = args[:data]
    labels     = args[:labels] || []
    unit       = args[:unit] || ''

    if multi
      return unk_msg("No data to check") unless data.is_a?(Array) && data.any?

      warnings = @options[:warning].split(',').map(&:to_f)
      criticals = @options[:critical].split(',').map(&:to_f)

      data.each_with_index do |val, idx|
        label = labels[idx] || "value#{idx + 1}"
        warn  = warnings[idx] rescue nil
        crit  = criticals[idx] rescue nil

        val = val.to_f
        message = "#{label}: #{val.round(2)}#{unit}"

        if crit && val >= crit
          @critical << message
        elsif warn && val >= warn
          @warning << message
        else
          @okays << message
        end

        warn_str = warn ? warn : ''
        crit_str = crit ? crit : ''
        build_perfdata(perfdata: "'#{label}'=#{val.round(2)}#{unit}", warning: warn_str, critical: crit_str)
      end

      build_final_output
    else
      if data
        warn_msg(@status_msg[:warn])
      else
        ok_msg(@status_msg[:ok])
      end
    end
  end


  # helper for excluding
  def exclude(args = {})
    data = args[:data]
    value = args[:value]
    data.delete_if { |item| /#{@options[:exclude]}/.match(item[value]) } unless @options[:exclude].to_s.empty?
  end

  # check for missing data
  def assert_required_keys!(hash, required_keys, context: 'data block')
    missing = required_keys.reject { |key| hash.key?(key) }
    unless missing.empty?
      unk_msg("Incomplete #{context} (Missing keys: #{missing.join(', ')})")
    end
  end

  # generate perfdata
  def build_perfdata(args = {})
    perfdata = args[:perfdata]
    warn     = args[:warning] || @options[:warning]
    crit     = args[:critical] || @options[:critical]
    @perfdata << "#{perfdata};#{warn};#{crit};;"
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
  def check_thresholds(args = {})
    data = args[:data]

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

  def url(args = {})
    path = args[:path]
    req  = args.fetch(:req, 'get')

    validate_connection_parameters!

    uri = URI("https://#{@options[:address]}:8006/#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @options[:insecure]
    http.read_timeout = 30  # Add timeout

    if req == 'post'
      request = Net::HTTP::Post.new(uri.request_uri)
      request.set_form_data('username' => @options[:username].to_s, 'password' => @options[:password].to_s)
    else
      fetch_cookie
      request = Net::HTTP::Get.new(uri.request_uri)
      request['cookie'] = @token
    end
    @response = http.request(request)
    rescue Timeout::Error => e
      unk_msg("Connection timeout: #{e.message}")
    rescue Errno::ECONNREFUSED => e
      unk_msg("Connection refused - check if PVE API is running: #{e.message}")
    rescue Errno::EHOSTUNREACH => e
      unk_msg("Host unreachable: #{e.message}")
    rescue OpenSSL::SSL::SSLError => e
      unk_msg("SSL connection error: #{e.message}")
    rescue StandardError => e
      unk_msg("Connection error: #{e.message}")
    end

  # Validate required connection parameters
  def validate_connection_parameters!
    unk_msg("Host address is required") if @options[:address].nil? || @options[:address].empty?
    unk_msg("Username is required") if @options[:username].nil? || @options[:username].empty?
    unk_msg("Password is required") if @options[:password].nil? || @options[:password].empty?
  end

  # check http response
  def check_http_response
    unk_msg(@response.message).to_s if @response.code != '200'
  end

  # init http req
  def http_connect(args = {})
    path = args[:path]
    req  = args.fetch(:req, 'get')
    url(path: path, req: req)
    puts "URL: #{path}" if @options[:debug]
    check_http_response

    begin
      parsed_response = JSON.parse(@response.body)
      @json_body = parsed_response['data']
      unk_msg("No data in API response") if @json_body.nil?
    rescue JSON::ParserError => e
      unk_msg("Invalid JSON response: #{e.message}")
    end

    puts JSON.pretty_generate(@json_body) if @options[:debug]
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
    unhealthy = @json_body.reject { |item| item['health'] == 'PASSED' || item['health'] == 'OK' }
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
    check_single_data(data: @json_body['status'] != 'active', message: @json_body['message'])
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
  def node_vm_helper(args = {})
    output_msg        = args[:output_msg]
    value             = args[:value]
    perf_label        = args.fetch(:perf_label, 'usage').downcase
    convert_value_to  = args.fetch(:convert_value_to, @options[:unit])
    value_to_compare  = args.fetch(:value_to_compare, '')
    convert_value(type: convert_value_to, value1: value, value2: value_to_compare)
    @message = "#{output_msg}: #{@usage}#{convert_value_to.upcase}"
    build_perfdata(perfdata: "'#{perf_label}'=#{@usage}#{convert_value_to.upcase}")
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
    node_vm_helper(value: @json_body['cpu'], output_msg: 'CPU usage', perf_label: 'cpu_usage', convert_value_to: '%')
  end

  ### node: cpu load
  def node_cpu_load
    return unless @options[:mode] == 'node-cpu-load'
    fetch_status_data

    loadavg = @json_body['loadavg']
    return unk_msg('Loadavg data not found') unless loadavg && loadavg.size == 3

    if @options[:percpu]
      number_of_cpus = @json_body['cpuinfo'] && @json_body['cpuinfo']['cpus']
      return unk_msg('CPU info not found') unless number_of_cpus && number_of_cpus > 0

      loadavg = loadavg.map { |v| v.to_f / number_of_cpus.to_f }
    end

    check_multiple_data(
      multi: true,
      data: loadavg,
      labels: ['load1', 'load5', 'load15'],
      unit: ''
    )
  end

  ### node: io wait
  def node_io_wait
    return unless @options[:mode] == 'node-io-wait'
    fetch_status_data
    node_vm_helper(value: @json_body['wait'], output_msg: 'IO Wait', perf_label: 'io_wait')
  end

  ### node: memory
  def node_memory_usage
    return unless @options[:mode] == 'node-memory-usage'
    fetch_status_data
    node_vm_helper(value: @json_body['memory']['used'], output_msg: 'Memory usage', perf_label: 'memory_usage', value_to_compare: @json_body['memory']['total'], convert_value_to: '%')
  end

  ### node: ksm
  def node_ksm_usage
    return unless @options[:mode] == 'node-ksm-usage'
    fetch_status_data
    node_vm_helper(value: @json_body['ksm']['shared'], output_msg: 'KSM sharing', perf_label: 'ksm_usage')
  end

  ### node: storage usage
  def node_storage_usage
    return unless @options[:mode] == 'node-storage-usage'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/storage/#{@options[:name]}/status")
    node_vm_helper(
      value: @json_body['used'],
      value_to_compare: @json_body['total'],
      output_msg: 'Storage usage',
      perf_label: 'storage_usage',
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
    required_keys = %w[netin]
    assert_required_keys!(@json_body[-1], required_keys, context: 'Node RRD data')
    node_vm_helper(value: @json_body[-1]['netin'], output_msg: 'Network usage in', perf_label: 'net_in_usage')
  end

  ### node: netout
  def node_net_out_usage
    return unless @options[:mode] == 'node-net-out-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[netout]
    assert_required_keys!(@json_body[-1], required_keys, context: 'Node RRD data')
    node_vm_helper(value: @json_body[-1]['netout'], output_msg: 'Network usage out', perf_label: 'net_out_usage')
  end

  ###--- QEMU, LXC CHECKS ---###
  # disk
  def vm_disk_write_usage
    return unless @options[:mode] == 'vm-disk-write-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[diskwrite]
    assert_required_keys!(@json_body[-1], required_keys, context: 'VM RRD data')
    node_vm_helper(value: @json_body[-1]['diskwrite'], output_msg: 'Disk write', perf_label: 'disk_write_usage')
  end

  def vm_disk_read_usage
    return unless @options[:mode] == 'vm-disk-read-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[diskread]
    assert_required_keys!(@json_body[-1], required_keys, context: 'VM RRD data')
    node_vm_helper(value: @json_body[-1]['diskread'], output_msg: 'Disk read', perf_label: 'disk_read_usage')
  end

  # status
  def vm_status
    return unless @options[:mode] == 'vm-status'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/#{@options[:type]}/#{@options[:vmid]}/status/current")
    current_vm_status = @json_body['status']

    case current_vm_status
    when 'running'
      ok_msg("Virtual Machine #{@options[:node]}/#{@options[:type]}/#{@options[:vmid]} is running")
    when 'stopped'
      crit_msg("Virtual Machine #{@options[:node]}/#{@options[:type]}/#{@options[:vmid]} is stopped")
    when 'paused'
      warn_msg("Virtual Machine #{@options[:node]}/#{@options[:type]}/#{@options[:vmid]} is paused")
    else
      crit_msg("Virtual Machine #{@options[:node]}/#{@options[:type]}/#{@options[:vmid]} is in unknown state: #{current_vm_status}")
    end
  end

  # cpu
  def vm_cpu_usage
    return unless @options[:mode] == 'vm-cpu-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[cpu]
    assert_required_keys!(@json_body[-1], required_keys, context: 'VM RRD data')
    node_vm_helper(value: @json_body[-1]['cpu'], output_msg: 'CPU usage', convert_value_to: '%', perf_label: 'cpu_usage')
  end

  # memory
  def vm_memory_usage
    return unless @options[:mode] == 'vm-memory-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[mem]
    assert_required_keys!(@json_body[-1], required_keys, context: 'VM RRD data')
    node_vm_helper(value: @json_body[-1]['mem'], output_msg: 'Memory usage', perf_label: 'memory_usage', value_to_compare: @json_body[-1]['maxmem'], convert_value_to: '%')
  end

  # network
  def vm_net_in_usage
    return unless @options[:mode] == 'vm-net-in-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[netin]
    assert_required_keys!(@json_body[-1], required_keys, context: 'VM RRD data')
    node_vm_helper(value: @json_body[-1]['netin'], output_msg: 'Network usage in', perf_label: 'net_in_usage')
  end

  def vm_net_out_usage
    return unless @options[:mode] == 'vm-net-out-usage'
    fetch_status_data(type: 'rrd')
    required_keys = %w[netout]
    assert_required_keys!(@json_body[-1], required_keys, context: 'VM RRD data')
    node_vm_helper(value: @json_body[-1]['netout'], output_msg: 'Network usage out', perf_label: 'net_out_usage')
  end

  ###--- MISC ---###
  # list nodes
  def list_nodes
    return unless @options[:mode] == 'list-nodes'
    http_connect(path: 'api2/json/nodes')
    puts "Node"
    @json_body.each do |node|
      puts node['node']
    end
    exit 0
  end

  # list vms
  def list_vms
    return unless @options[:mode] == 'list-vms'
    http_connect(path: 'api2/json/nodes')
    puts "Node       Type     Id     Name"
    @json_body.each do |node|
      node_name = node['node']

      # QEMU VMs
      http_connect(path: "api2/json/nodes/#{node_name}/qemu")
      qemus = @json_body.map do |vm|
        [node_name.ljust(10), 'qemu'.ljust(8), vm['vmid'].to_s.ljust(6), vm['name']]
      end

      # LXC Container
      http_connect(path: "api2/json/nodes/#{node_name}/lxc")
      lxcs = @json_body.map do |vm|
        [node_name.ljust(10), 'lxc'.ljust(8), vm['vmid'].to_s.ljust(6), vm['name']]
      end

      (qemus + lxcs).each { |line| puts line.join(' ') }
    end
    exit 0
  end
end

CheckPve.new(options)
