module Agents
  class CallistoNetworkAgent < Agent
    include FormConfigurable
    can_dry_run!
    no_bulk_receive!
    default_schedule 'every_1h'

    description <<-MD
      The Callisto Network Agent interacts with rpc server from Callisto Network and can create events / tasks if wanted / needed.

      The `type` can be like checking the wallet's balance.

      The `wallet` is needed for interaction about balance for example.

      The `debug` can add verbosity.

      The `rpc_server` is needed for interaction with the api (per default thenode from callisto.network)

      Set `expected_update_period_in_days` to the maximum amount of time that you'd expect to pass between Events being created by this Agent.

    MD

    event_description <<-MD
      Events look like this:

          {
            "jsonrpc": "2.0",
            "id": 1,
            "result": 7116789.692103207
          }
    MD

    def default_options
      {
        'type' => '',
        'wallet' => '',
        'rpc_server' => 'https://rpc.callisto.network/',
        'debug' => 'false',
        'emit_events' => 'true',
        'expected_receive_period_in_days' => '2',
        'changes_only' => 'true'
      }
    end

    form_configurable :debug, type: :boolean
    form_configurable :emit_events, type: :boolean
    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :changes_only, type: :boolean
    form_configurable :type, type: :array, values: ['get_balance', 'net_peerCount', 'net_version', 'eth_protocolVersion', 'eth_gasPrice', 'eth_getTransactionCount', 'stake_reward']
    form_configurable :wallet, type: :string
    form_configurable :rpc_server, type: :string
    def validate_options
      errors.add(:base, "type has invalid value: should be 'get_balance' 'net_peerCount' 'net_version' 'eth_protocolVersion' 'eth_gasPrice' 'eth_getTransactionCount' 'stake_reward'") if interpolated['type'].present? && !%w(get_balance net_peerCount net_version eth_protocolVersion eth_gasPrice eth_getTransactionCount stake_reward).include?(interpolated['type'])

      unless options['rpc_server'].present?
        errors.add(:base, "rpc_server is a required field")
      end

      unless options['wallet'].present?
        errors.add(:base, "wallet is a required field")
      end

      if options.has_key?('emit_events') && boolify(options['emit_events']).nil?
        errors.add(:base, "if provided, emit_events must be true or false")
      end

      if options.has_key?('changes_only') && boolify(options['changes_only']).nil?
        errors.add(:base, "if provided, changes_only must be true or false")
      end

      if options.has_key?('debug') && boolify(options['debug']).nil?
        errors.add(:base, "if provided, debug must be true or false")
      end

      unless options['expected_receive_period_in_days'].present? && options['expected_receive_period_in_days'].to_i > 0
        errors.add(:base, "Please provide 'expected_receive_period_in_days' to indicate how many days can pass before this Agent is considered to be not working")
      end
    end

    def working?
      event_created_within?(options['expected_receive_period_in_days']) && !recent_error_logs?
    end

    def receive(incoming_events)
      incoming_events.each do |event|
        interpolate_with(event) do
          log event
          trigger_action
        end
      end
    end

    def check
      trigger_action
    end

    private

    def log_curl_output(code,body)

      log "request status : #{code}"

      if interpolated['debug'] == 'true'
        log "body"
        log body
      end

    end

    def stake_reward()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump([
        {
          "id" => "baccb9edcfeaacc09f666621eac70e72",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x08A7c8be47773546DC5E173d67B0c38AfFfa4b84",
              "data" => "0xbf92b4ef000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        }
      ])
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['stake_reward']
          memory['stake_reward'] = payload.to_s
          payload[0]['result'] = payload[0]['result'].to_i(16)
          create_event payload: payload[0]
        end
      else
        if payload.to_s != memory['stake_reward']
          memory['stake_reward'] = payload.to_s
        end
        payload['result'] = payload['result'].to_i(16)
        create_event payload: payload[0]
      end
    end

    def eth_getTransactionCount()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "eth_getTransactionCount",
        "params" => [
          "#{interpolated['wallet']}",
          "latest"
        ],
        "id" => 1,
        "jsonrpc" => "2.0"
      })
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['eth_getTransactionCount']
          memory['eth_getTransactionCount'] = payload.to_s
          payload['result'] = payload['result'].to_i(16)
          create_event payload: payload
        end
      else
        if payload.to_s != memory['eth_getTransactionCount']
          memory['eth_getTransactionCount'] = payload.to_s
        end
        payload['result'] = payload['result'].to_i(16)
        create_event payload: payload
      end
    end

    def eth_gasPrice()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "eth_gasPrice",
        "params" => [],
        "id" => 67,
        "jsonrpc" => "2.0"
      })
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['eth_gasPrice']
          memory['eth_gasPrice'] = payload.to_s
          payload['result'] = payload['result'].to_i(16)
          create_event payload: payload
        end
      else
        if payload.to_s != memory['eth_gasPrice']
          memory['eth_gasPrice'] = payload.to_s
        end
        payload['result'] = payload['result'].to_i(16)
        create_event payload: payload
      end
    end

    def eth_protocolVersion()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "eth_protocolVersion",
        "params" => [],
        "id" => 67,
        "jsonrpc" => "2.0"
      })
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['eth_protocolVersion']
          memory['eth_protocolVersion'] = payload.to_s
          payload['result'] = payload['result'].to_i(16)
          create_event payload: payload
        end
      else
        if payload.to_s != memory['eth_protocolVersion']
          memory['eth_protocolVersion'] = payload.to_s
        end
        payload['result'] = payload['result'].to_i(16)
        create_event payload: payload
      end
    end

    def net_version()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "net_version",
        "params" => [],
        "id" => 67,
        "jsonrpc" => "2.0"
      })
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['net_version']
          memory['net_version'] = payload.to_s
          payload['result'] = payload['result'].to_i(16)
          create_event payload: payload
        end
      else
        if payload.to_s != memory['net_version']
          memory['net_version'] = payload.to_s
        end
        payload['result'] = payload['result'].to_i(16)
        create_event payload: payload
      end
    end

    def net_peerCount()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "net_peerCount",
        "params" => [],
        "id" => 74,
        "jsonrpc" => "2.0"
      })
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['net_peerCount']
          memory['net_peerCount'] = payload.to_s
          payload['result'] = payload['result'].to_i(16)
          create_event payload: payload
        end
      else
        if payload.to_s != memory['net_peerCount']
          memory['net_peerCount'] = payload.to_s
        end
        payload['result'] = payload['result'].to_i(16)
        create_event payload: payload
      end
    end

    def get_balance()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "eth_getBalance",
        "params" => [
          "#{interpolated['wallet']}",
          "latest"
        ],
        "id" => 1,
        "jsonrpc" => "2.0"
      })
      
      req_options = {
        use_ssl: uri.scheme == "https",
      }
      
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['get_balance']
          memory['get_balance'] = payload.to_s
          power = (10 ** 18).to_i
          payload['result'] = payload['result'].to_i(16) / power.to_i.to_f
          create_event payload: payload
        end
      else
        if payload.to_s != memory['get_balance']
          memory['get_balance'] = payload.to_s
        end
        power = (10 ** 18).to_i
        payload['result'] = payload['result'].to_i(16) / power.to_i.to_f
        create_event payload: payload
      end
    end

    def trigger_action

      case interpolated['type']
      when "get_balance"
        get_balance()
      when "net_peerCount"
        net_peerCount()
      when "net_version"
        net_version()
      when "eth_protocolVersion"
        eth_protocolVersion()
      when "eth_gasPrice"
        eth_gasPrice()
      when "eth_getTransactionCount"
        eth_getTransactionCount()
      when "stake_reward"
        stake_reward()
      else
        log "Error: type has an invalid value (#{type})"
      end
    end
  end
end
