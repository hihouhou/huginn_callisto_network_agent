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
    form_configurable :type, type: :array, values: ['get_balance', 'net_peerCount', 'net_version', 'eth_protocolVersion', 'eth_gasPrice', 'eth_getTransactionCount', 'stake_reward_clo', 'get_tokens_balance', 'eth_getBlockByNumber', 'soy_farming_soy_clo_pending_rewards', 'soy_farming_soy_cloe_pending_rewards', 'stake_reward_soy', 'soy_farming_soy_btt_pending_rewards', 'soy_cs_pending_rewards']
    form_configurable :wallet, type: :string
    form_configurable :rpc_server, type: :string
    def validate_options
      errors.add(:base, "type has invalid value: should be 'get_balance' 'net_peerCount' 'net_version' 'eth_protocolVersion' 'eth_gasPrice' 'eth_getTransactionCount' 'stake_reward_clo' 'get_tokens_balance' 'eth_getBlockByNumber' 'soy_farming_soy_clo_pending_rewards' 'soy_farming_soy_cloe_pending_rewards' 'stake_reward_soy' 'soy_farming_soy_btt_pending_rewards' 'soy_cs_pending_rewards'") if interpolated['type'].present? && !%w(get_balance net_peerCount net_version eth_protocolVersion eth_gasPrice eth_getTransactionCount stake_reward_clo get_tokens_balance eth_getBlockByNumber soy_farming_soy_clo_pending_rewards soy_farming_soy_cloe_pending_rewards stake_reward_soy soy_farming_soy_btt_pending_rewards soy_cs_pending_rewards).include?(interpolated['type'])

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

    def test_create(day,line,last_status,i)
      power = (10 ** 18).to_i
      history = (i - 1).step(last_status['result'][2..].chars.each_slice(64).map(&:join).size - 1, i).map { |b| last_status['result'][2..].chars.each_slice(64).map(&:join)[b] }
      if interpolated['debug'] == 'true'
        log "new -> #{line.to_i(16) / power.to_i.to_f} / history #{history[0].to_i(16) / power.to_i.to_f}"
      end
      if line != history[0]
        create_event :payload => { 'wallet' => "#{interpolated['wallet']}", 'period_in_days' => "#{day}", 'pending_rewards' => "#{line.to_i(16) / power.to_i.to_f}"}
      end
    end

    def soy_cs_pending_rewards()

      uri = URI.parse("https://rpc.callisto.network/")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request["Authority"] = "rpc.callisto.network"
      request["Accept"] = "*/*"
      request["Accept-Language"] = "fr;q=0.7"
      request["Cache-Control"] = "no-cache"
      request["Origin"] = "https://app.soy.finance"
      request["Pragma"] = "no-cache"
      request["Referer"] = "https://app.soy.finance/"
      request["Sec-Fetch-Dest"] = "empty"
      request["Sec-Fetch-Mode"] = "cors"
      request["Sec-Fetch-Site"] = "cross-site"
      request["Sec-Gpc"] = "1"
      request["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"
      request.body = JSON.dump({
        "jsonrpc" => "2.0",
        "id" => 4043350105485278,
        "method" => "eth_call",
        "params" => [
          {
            "data" => "0x252dba420000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000003e0000000000000000000000000ff9289c2656ca1d194dea1895aaf3278b744fa7000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024f40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}0000000000000000000000000000000000000000000000000000000000000000000000000000000086f7e2ef599690b64f0063b3f978ea6ae2814f6300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024f40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}000000000000000000000000000000000000000000000000000000000000000000000000000000007d6c70b6561c31935e6b0dd77731fc63d5ac37f200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024f40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}0000000000000000000000000000000000000000000000000000000000000000000000000000000019dcb402162b6937a8aceac87ed6c05219c9bef700000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024f40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}0000000000000000000000000000000000000000000000000000000000000000000000000000000031bff88c6124e1622f81b3ba7ed219e5d78abd9800000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024f40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}00000000000000000000000000000000000000000000000000000000000000000000000000000000eb4511c90f9387de8f8945abd8c803d5cb27550900000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000024bf92b4ef000000000000000000000000#{interpolated['wallet'][2..-1]}00000000000000000000000000000000000000000000000000000000",
            "to" => "0x3c4127a01b75e3741dd40a7a044bc70e3ed4e77c"
          },
          "latest"
        ]
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
        if payload.to_s != memory['soy_cs_pending_rewards']
          i = 0
          last_status = memory['soy_cs_pending_rewards'].gsub("=>", ": ").gsub(": nil,", ": null,")
          last_status = JSON.parse(last_status)
          payload['result'][2..].chars.each_slice(64).map(&:join).each do |line|
            i = i + 1
            case i
            when 11
              day = 7
              if interpolated['debug'] == 'true'
                log "for #{day} days"
              end
              test_create(day,line,last_status,i)
            when 13
              day = 30
              if interpolated['debug'] == 'true'
                log "for #{day} days"
              end
              test_create(day,line,last_status,i)
            when 15
              day = 91
              if interpolated['debug'] == 'true'
                log "for #{day} days"
              end
              test_create(day,line,last_status,i)
            when 17
              day = 182
              if interpolated['debug'] == 'true'
                log "for #{day} days"
              end
              test_create(day,line,last_status,i)
            when 19
              day = 365
              if interpolated['debug'] == 'true'
                log "for #{day} days"
              end
              test_create(day,line,last_status,i)
            end
            memory['soy_cs_pending_rewards'] = payload.to_s
          end
        end
      else
        memory['soy_cs_pending_rewards'] = payload.to_s
        create_event payload: payload[0]
      end
    end

    def soy_farming_soy_btt_pending_rewards()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json; charset=UTF-8"
      request["Accept"] = "application/json, text/plain, */*"
      request.body = JSON.dump([
        {
          "id" => "d21a3c1c25918de198ed446c67b5983f",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x8967a2adc0e1b7b0422426e350fe389a4745ec78",
              "data" => "0xf40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}"
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
        if payload.to_s != memory['soy_farming_soy_btt']
          memory['soy_farming_soy_btt'] = payload.to_s
          power = (10 ** 18).to_i
          payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
          log payload
          create_event payload: payload[0]
        end
      else
        memory['soy_farming_soy_btt'] = payload.to_s
        create_event payload: payload[0]
      end
    end

    def stake_reward_soy()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump([
        {
          "id" => "788b52b2b4c0b03223e11841036a32fe",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0xeB4511C90F9387De8F8945ABD8C803d5cB275509",
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
        if payload.to_s != memory['stake_reward_soy']
          memory['stake_reward_soy'] = payload.to_s
          if payload[0].key?("result")
            power = (10 ** 18).to_i
            payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
            payload[0]['name'] = "soy"
            payload[0]['symbol'] = "SOY"
          end
          create_event payload: payload[0]
        end
      else
        if payload.to_s != memory['stake_reward_soy']
          memory['stake_reward_soy'] = payload.to_s
        end
        power = (10 ** 18).to_i
        payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
        payload[0]['name'] = "soy"
        payload[0]['symbol'] = "SOY"
        create_event payload: payload[0]
      end
    end

    def soy_farming_soy_clo_pending_rewards()
#      payload = {}
#      callisto_rpc = Eth::Client.create "#{interpolated['rpc_server']}"
#      ens_registry_abi = '[{"type":"constructor","stateMutability":"nonpayable","inputs":[{"type":"address","name":"_rewardsDistribution","internalType":"address"},{"type":"address","name":"_rewardsToken","internalType":"address"},{"type":"address","name":"_lpToken","internalType":"address"}]},{"type":"event","name":"EmergencyWithdraw","inputs":[{"type":"address","name":"user","internalType":"address","indexed":true},{"type":"uint256","name":"amount","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"OwnershipTransferred","inputs":[{"type":"address","name":"previousOwner","internalType":"address","indexed":true},{"type":"address","name":"newOwner","internalType":"address","indexed":true}],"anonymous":false},{"type":"event","name":"RewardAdded","inputs":[{"type":"uint256","name":"reward","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"RewardPaid","inputs":[{"type":"address","name":"user","internalType":"address","indexed":true},{"type":"uint256","name":"reward","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Staked","inputs":[{"type":"address","name":"user","internalType":"address","indexed":true},{"type":"uint256","name":"amount","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"event","name":"Withdraw","inputs":[{"type":"address","name":"user","internalType":"address","indexed":true},{"type":"uint256","name":"amount","internalType":"uint256","indexed":false}],"anonymous":false},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"accumulatedRewardPerShare","inputs":[]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"emergencyWithdraw","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"getAllocationX1000","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"getRewardPerSecond","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"address","name":"","internalType":"address"}],"name":"globalFarm","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"bool","name":"","internalType":"bool"}],"name":"isOwner","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"lastRewardTimestamp","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"limitAmount","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"address","name":"","internalType":"contract IERC223"}],"name":"lpToken","inputs":[]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"notifyRewardAmount","inputs":[{"type":"uint256","name":"reward","internalType":"uint256"}]},{"type":"function","stateMutability":"view","outputs":[{"type":"address","name":"","internalType":"address"}],"name":"owner","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"","internalType":"uint256"}],"name":"pendingReward","inputs":[{"type":"address","name":"_user","internalType":"address"}]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"renounceOwnership","inputs":[]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"rescueERC20","inputs":[{"type":"address","name":"token","internalType":"address"},{"type":"address","name":"to","internalType":"address"}]},{"type":"function","stateMutability":"view","outputs":[{"type":"address","name":"","internalType":"contract IERC223"}],"name":"rewardsToken","inputs":[]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"tokenReceived","inputs":[{"type":"address","name":"_from","internalType":"address"},{"type":"uint256","name":"_amount","internalType":"uint256"},{"type":"bytes","name":"_data","internalType":"bytes"}]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"transferOwnership","inputs":[{"type":"address","name":"newOwner","internalType":"address"}]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"update","inputs":[]},{"type":"function","stateMutability":"view","outputs":[{"type":"uint256","name":"amount","internalType":"uint256"},{"type":"uint256","name":"rewardDebt","internalType":"uint256"}],"name":"userInfo","inputs":[{"type":"address","name":"","internalType":"address"}]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"withdraw","inputs":[{"type":"uint256","name":"_amount","internalType":"uint256"}]},{"type":"function","stateMutability":"nonpayable","outputs":[],"name":"withdrawInactiveReward","inputs":[]}]'
#      ens_registry_address = "0xf43Db9BeC8F8626Cb5ADD409C7EBc7272c8f5F8f"
#      ens_registry_name = "SOYLocalFarm"
#      ens_registry = Eth::Contract.from_abi(name: ens_registry_name, address: ens_registry_address, abi: ens_registry_abi)
#      power = (10 ** 18).to_i
#      payload['pending_rewards'] = callisto_rpc.call(ens_registry, "pendingReward", "#{interpolated['wallet']}") / power.to_i.to_f
#      payload['staked_token'] = callisto_rpc.call(ens_registry, "userInfo", "#{interpolated['wallet']}")[0] / power.to_i.to_f
#
#      if interpolated['debug'] == 'true'
#        log "payload"
#        log payload
#      end

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json; charset=UTF-8"
      request["Accept"] = "application/json, text/plain, */*"
      request.body = JSON.dump([
        {
          "id" => "0f206bc0047f6b44cb8f118240b8e351",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0xf43Db9BeC8F8626Cb5ADD409C7EBc7272c8f5F8f",
              "data" => "0xf40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}"
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
        if payload.to_s != memory['soy_farming_soy_clo']
          memory['soy_farming_soy_clo'] = payload.to_s
          power = (10 ** 18).to_i
          payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
          log payload
          create_event payload: payload[0]
        end
      else
        memory['soy_farming_soy_clo'] = payload.to_s
        create_event payload: payload[0]
      end
    end

    def soy_farming_soy_cloe_pending_rewards()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json; charset=UTF-8"
      request["Accept"] = "application/json, text/plain, */*"
      request.body = JSON.dump([
        {
          "id" => "0f206bc0047f6b44cb8f118240b8e351",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x8c0a982a4193c6bf8eea6637db0cf9160dcf91fd",
              "data" => "0xf40f0f52000000000000000000000000#{interpolated['wallet'][2..-1]}"
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
        if payload.to_s != memory['soy_farming_soy_cloe']
          memory['soy_farming_soy_cloe'] = payload.to_s
          power = (10 ** 18).to_i
          payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
          log payload
          create_event payload: payload[0]
        end
      else
        memory['soy_farming_soy_cloe'] = payload.to_s
        create_event payload: payload[0]
      end
    end

    def eth_getBlockByNumber()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "jsonrpc" => "2.0",
        "method" => "eth_getBlockByNumber",
        "params" => [
          "latest",
          false
        ],
        "id" => 1
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
        if payload.to_s != memory['eth_getBlockByNumber']
          memory['eth_getBlockByNumber'] = payload.to_s
          if payload.key?("result")
            payload['result']['number'] = payload['result']['number'].to_i(16)
            payload['result']['timestamp'] = payload['result']['timestamp'].to_i(16)
            payload['result']['difficulty'] = payload['result']['difficulty'].to_i(16)
            payload['result']['extraData'] = payload['result']['extraData'].to_i(16)
            payload['result']['gasLimit'] = payload['result']['gasLimit'].to_i(16)
            payload['result']['gasUsed'] = payload['result']['gasUsed'].to_i(16)
            payload['result']['nonce'] = payload['result']['nonce'].to_i(16)
            payload['result']['size'] = payload['result']['size'].to_i(16)
            payload['result']['totalDifficulty'] = payload['result']['totalDifficulty'].to_i(16)
            payload['result']['name'] = "callisto"
            payload['result']['symbol'] = "CLO"
          end
          create_event payload: payload
        end
      else
        if payload.to_s != memory['eth_getBlockByNumber']
          memory['eth_getBlockByNumber'] = payload.to_s
        end
        payload['result']['number'] = payload['result']['number'].to_i(16)
        payload['result']['timestamp'] = payload['result']['timestamp'].to_i(16)
        payload['result']['difficulty'] = payload['result']['difficulty'].to_i(16)
        payload['result']['extraData'] = payload['result']['extraData'].to_i(16)
        payload['result']['gasLimit'] = payload['result']['gasLimit'].to_i(16)
        payload['result']['gasUsed'] = payload['result']['gasUsed'].to_i(16)
        payload['result']['nonce'] = payload['result']['nonce'].to_i(16)
        payload['result']['size'] = payload['result']['size'].to_i(16)
        payload['result']['totalDifficulty'] = payload['result']['totalDifficulty'].to_i(16)
        payload['result']['name'] = "callisto"
        payload['result']['symbol'] = "CLO"
        create_event payload: payload
      end
    end

    def get_tokens_balance()

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json; charset=UTF-8"
      request["Accept"] = "application/json, text/plain, */*"
      request.body = JSON.dump([
        {
          "id" => "65b0be964fde4eacba0c993a7bd4caaa",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x1eAa43544dAa399b87EEcFcC6Fa579D5ea4A6187",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        },
        {
          "id" => "e2a10af788ec1d4afa57558a857b9319",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x6182d2cd59227c20B486a53976dcEeAF38e76Eed",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        },
        {
          "id" => "b4bef730614cb7cbc6585c7e963029d3",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0xcC00860947035a26Ffe24EcB1301ffAd3a89f910",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        },
        {
          "id" => "dfab9e50ca9e48c1fb9f2ca9c009ea58",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0xCC78D0A86B0c0a3b32DEBd773Ec815130F9527CF",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        },
        {
          "id" => "a891c856974b2c71d7b99f2c056585d6",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0xbf6c50889d3a620eb42C0F188b65aDe90De958c4",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        },
        {
          "id" => "1b3b1a0f2c708f8c71bf3d94246ec698",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x9FaE2529863bD691B4A7171bDfCf33C7ebB10a65",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
            },
            "latest"
          ]
        },
        {
          "id" => "ab9c68381989f3e3e47fb163244d7bf2",
          "jsonrpc" => "2.0",
          "method" => "eth_call",
          "params" => [
            {
              "to" => "0x83736D58F496afab4cF7D8453575ab59279810ec",
              "data" => "0x70a08231000000000000000000000000#{interpolated['wallet'][2..-1]}"
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
      fixed_payload = JSON.parse(response.body)

      if interpolated['changes_only'] == 'true'
        if payload.to_s != memory['get_tokens_balance']
          if "#{memory['get_tokens_balance']}" == ''
            payload.each do | token |
              case token['id']
              when "65b0be964fde4eacba0c993a7bd4caaa"
                token['name'] = "Callisto Enterprise"
                token['symbol'] = "CLOE"
              when "1b3b1a0f2c708f8c71bf3d94246ec698"
                token['name'] = "SOY Finance"
                token['symbol'] = "SOY"
              when "a891c856974b2c71d7b99f2c056585d6"
                token['name'] = "Bulls USD"
                token['symbol'] = "BUSDT"
              else
                token['name'] = "Unknown"
                token['symbol'] = "Unknown"
              end
              power = (10 ** 18).to_i
              token['result'] = token['result'].to_i(16) / power.to_i.to_f
              create_event payload: token
            end
          else
            last_status = memory['get_tokens_balance'].gsub("=>", ": ").gsub(": nil,", ": null,")
            last_status = JSON.parse(last_status)
            payload.each do | token |
              found = false
              last_status.each do | tokenbis|
                if token == tokenbis
                  found = true
                end
              end
              if found == false
                case token['id']
                when "65b0be964fde4eacba0c993a7bd4caaa"
                  token['name'] = "Callisto Enterprise"
                  token['symbol'] = "CLOE"
                when "1b3b1a0f2c708f8c71bf3d94246ec698"
                  token['name'] = "SOY Finance"
                  token['symbol'] = "SOY"
                else
                  token['name'] = "Unknown"
                  token['symbol'] = "Unknown"
                end
                power = (10 ** 18).to_i
                token['result'] = token['result'].to_i(16) / power.to_i.to_f
                create_event payload: token
              end
            end
          end
          memory['get_tokens_balance'] = fixed_payload.to_s
        end
      else
        if payload.to_s != memory['get_tokens_balance']
          memory['get_tokens_balance']= fixed_payload.to_s
        end
        power = (10 ** 18).to_i
        payload.each do | token |
          token['result'] = token['result'].to_i(16) / power.to_i.to_f
          create_event payload: token
        end
      end
    end

    def stake_reward_clo()

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
        if payload.to_s != memory['stake_reward_clo']
          memory['stake_reward_clo'] = payload.to_s
          if payload[0].key?("result")
            power = (10 ** 18).to_i
            payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
            payload[0]['name'] = "callisto"
            payload[0]['symbol'] = "CLO"
          end
          create_event payload: payload[0]
        end
      else
        if payload.to_s != memory['stake_reward_clo']
          memory['stake_reward_clo'] = payload.to_s
        end
        power = (10 ** 18).to_i
        payload[0]['result'] = payload[0]['result'].to_i(16) / power.to_i.to_f
        payload[0]['name'] = "callisto"
        payload[0]['symbol'] = "CLO"
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
          payload['name'] = "callisto"
          payload['symbol'] = "CLO"
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
      when "stake_reward_clo"
        stake_reward_clo()
      when "get_tokens_balance"
        get_tokens_balance()
      when "eth_getBlockByNumber"
        eth_getBlockByNumber()
      when "soy_farming_soy_clo_pending_rewards"
        soy_farming_soy_clo_pending_rewards()
      when "soy_farming_soy_cloe_pending_rewards"
        soy_farming_soy_cloe_pending_rewards()
      when "stake_reward_soy"
        stake_reward_soy()
      when "soy_farming_soy_btt_pending_rewards"
        soy_farming_soy_btt_pending_rewards()
      when "soy_cs_pending_rewards"
        soy_cs_pending_rewards()
      else
        log "Error: type has an invalid value (#{type})"
      end
    end
  end
end
