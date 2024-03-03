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

      The `wallet_password` is needed for unlocking a wallet when you want to send CLO.

      The `value` is needed when you want to send CLO.

      The `round` is needed when you want to do CLO coldstacking.

      The `wallet_dest` is needed  when you want to send CLO.

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
        'wallet_password' => '',
        'value' => '',
        'round' => '',
        'wallet_dest' => '',
        'changes_only' => 'true',
        'filter_for_method_id' => '',
        'first_block' => '',
        'last_block' => '',
        'sql_db' => ''
      }
    end

    form_configurable :debug, type: :boolean
    form_configurable :emit_events, type: :boolean
    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :changes_only, type: :boolean
    form_configurable :type, type: :array, values: ['get_balance', 'net_peerCount', 'net_version', 'eth_protocolVersion', 'eth_gasPrice', 'eth_getTransactionCount', 'stake_reward_clo', 'get_tokens_balance', 'eth_getBlockByNumber', 'soy_farming_soy_clo_pending_rewards', 'soy_farming_soy_cloe_pending_rewards', 'stake_reward_soy', 'soy_farming_soy_btt_pending_rewards', 'soy_cs_pending_rewards', 'clo_sendtx', 'get_tx_by_address_with_filter', 'start_cs_clo', 'withdraw_cs_clo', 'get_tx_stats', 'callosha_slots', '2bears_check_order_by_id', 'get_abi_json']
    form_configurable :wallet, type: :string
    form_configurable :rpc_server, type: :string
    form_configurable :wallet_password, type: :string
    form_configurable :value, type: :string
    form_configurable :round, type: :string
    form_configurable :wallet_dest, type: :string
    form_configurable :filter_for_method_id, type: :string
    form_configurable :first_block, type: :string
    form_configurable :last_block, type: :string
    form_configurable :sql_db, type: :string
    def validate_options
      errors.add(:base, "type has invalid value: should be 'get_balance' 'net_peerCount' 'net_version' 'eth_protocolVersion' 'eth_gasPrice' 'eth_getTransactionCount' 'stake_reward_clo' 'get_tokens_balance' 'eth_getBlockByNumber' 'soy_farming_soy_clo_pending_rewards' 'soy_farming_soy_cloe_pending_rewards' 'stake_reward_soy' 'soy_farming_soy_btt_pending_rewards' 'soy_cs_pending_rewards' 'clo_sendtx' 'get_tx_by_address_with_filter' 'start_cs_clo' 'withdraw_cs_clo' 'get_tx_stats' 'callosha_slots' '2bears_check_order_by_id' 'get_abi_json'") if interpolated['type'].present? && !%w(get_balance net_peerCount net_version eth_protocolVersion eth_gasPrice eth_getTransactionCount stake_reward_clo get_tokens_balance eth_getBlockByNumber soy_farming_soy_clo_pending_rewards soy_farming_soy_cloe_pending_rewards stake_reward_soy soy_farming_soy_btt_pending_rewards soy_cs_pending_rewards clo_sendtx get_tx_by_address_with_filter start_cs_clo withdraw_cs_clo get_tx_stats callosha_slots 2bears_check_order_by_id get_abi_json).include?(interpolated['type'])

      unless options['wallet_password'].present? || !['clo_sendtx' 'start_cs_clo' 'withdraw_cs_clo'].include?(options['type'])
        errors.add(:base, "wallet_password is a required field")
      end

      unless options['value'].present? || !['clo_sendtx' 'start_cs_clo' 'callosha_slots' '2bears_check_order_by_id'].include?(options['type'])
        errors.add(:base, "value is a required field")
      end

      unless options['wallet_dest'].present? || !['clo_sendtx'].include?(options['type'])
        errors.add(:base, "wallet_dest is a required field")
      end

      unless options['round'].present? || !['start_cs_clo' 'callosha_slots'].include?(options['type'])
        errors.add(:base, "round is a required field")
      end

      unless options['rpc_server'].present?
        errors.add(:base, "rpc_server is a required field")
      end

      unless options['wallet'].present? || !['get_balance' 'eth_getTransactionCount' 'stake_reward_clo' 'get_tokens_balance' 'eth_getBlockByNumber' 'soy_farming_soy_clo_pending_rewards' 'soy_farming_soy_cloe_pending_rewards' 'stake_reward_soy' 'soy_farming_soy_btt_pending_rewards' 'soy_cs_pending_rewards' 'clo_sendtx' 'get_tx_by_address_with_filter' 'start_cs_clo' 'callosha_slots' 'get_abi_json'].include?(options['type'])
        errors.add(:base, "wallet is a required field")
      end

      unless options['first_block'].present? || !['get_tx_stats'].include?(options['type'])
        errors.add(:base, "first_block is a required field")
      end

      unless options['last_block'].present? || !['get_tx_by_address_with_filter' 'get_tx_stats'].include?(options['type'])
        errors.add(:base, "last_block is a required field")
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

    def max_gain(contract)
      internal = true
      balance = get_balance(internal,contract)
      max_gain_for_1000 = balance * 0.7
      max_gain_for_1 = max_gain_for_1000 / 1000
      max_gain = interpolated['value'].to_i * max_gain_for_1
      if interpolated['debug'] == 'true'
        log "bank balance : #{balance}"
        log "max gain for 1000 : #{max_gain_for_1000}"
        log "max gain for 1 : #{max_gain_for_1}"
        log "max gain : #{max_gain}"
      end
      return max_gain

    end

    def to_hex(value, length = 64, with_0x = false)
#      log value
#      log value.class
      hex = value.to_s(16)
      hex = hex.rjust(length, '0')
      hex = hex.sub(/^0x/, '') unless with_0x
      hex = "0x" + hex if with_0x
      hex
    end

    def log_curl_output(code,body)

      if interpolated['debug'] == 'true'
        log "request status : #{code}"
        log "body"
        log body
      end

    end

    def find_symbol(contract)

      case contract
      when "0x9fae2529863bd691b4a7171bdfcf33c7ebb10a65"
        found_symbol = 'SOY'
      when "0x1eaa43544daa399b87eecfcc6fa579d5ea4a6187"
        found_symbol = 'CLOE'
      when "0xbf6c50889d3a620eb42c0f188b65ade90de958c4"
        found_symbol = 'BUSDT'
      else
        found_symbol = 'unknown'
      end
      return found_symbol
    end

    def owner_finder(address=interpolated['wallet'])

      db = SQLite3::Database.new(interpolated['sql_db'])
      result = db.get_first_row('SELECT name FROM directory WHERE address = ?', address)
      db.close

      if result
        if interpolated['debug'] == 'true'
          log "#{result[0]} found in sqldb"
        end
        return result[0]
      else
        if interpolated['debug'] == 'true'
          log "nothing found in sqldb"
        end
        return nil
      end
    end

    def function_finder(contract_address=interpolated['wallet'],bytes_signature)

      db = SQLite3::Database.new(interpolated['sql_db'])
      result = db.get_first_row('SELECT text_signature FROM signatures WHERE bytes_signature = ? AND contract_address = ?', bytes_signature, contract_address)
      db.close

      if result
        return result[0].split('(').first
      else
        db = SQLite3::Database.new(interpolated['sql_db'])
        result = db.get_first_row('SELECT text_signature FROM signatures WHERE bytes_signature = ?', bytes_signature)
        db.close
        if result
          return result[0].split('(').first
        else
          return 'unknown'
        end
      end
    end

    def get_abi_json(contract_address,internal=false)

      uri = URI.parse("https://explorer.callisto.network/api?module=contract&action=getabi&address=#{contract_address}")
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"

      req_options = {
        use_ssl: uri.scheme == "https",
      }

      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)

      payload = JSON.parse(response.body)

      if internal == false
        create_event payload: payload
      else
        return payload
      end

    end

    def get_tx_receipt(hash)

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "eth_getTransactionReceipt",
        "params" => [
          "#{hash}"
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

      return JSON.parse(response.body)

    end

    def percentage(number, total)
#      log number
#      log total
      (number/total.to_f*100).round(2)
    end

    def most_common_from(transactions)
      seen = {}
      transactions.each do |tx|
        seen[tx['from']] = (seen[tx['from']] || 0) + 1
      end
      seen.keys.max_by { |k| seen[k] }
    end

    def counter(list,patterns)
      total = 0
      
      list.each do |element|
        from_value = element["from"].downcase
        if patterns.include?(from_value)
          total += 1
        end
      end
      return total
    end

    def callosha_slots()

      internal = true
      contract = "0x7777265DC7FD2a15A7f2E8d8Ad87b3DAec677777"
      power_of_10 = 18
      final_value = interpolated['value'].to_i * 10**power_of_10
#      log "0x83f818b4000000000000000000000000000000000000000000000000016345785d8a00000000000000000000000000000000000000000000000000000000000000000001"
#      log "0x83f818b4#{to_hex(max_gain(contract).to_i)}#{to_hex(interpolated['round'].to_i)}"
      if interpolated['debug'] == 'true'
        log "unlocking the wallet"
      end
      response = JSON.parse(unlock_wallet())
      log "response -> #{response}"
      log "response result -> #{response['result']}"
      if response['result'] == true
        if interpolated['debug'] == 'true'
          log "the wallet is unlocked"
        end
        uri = URI.parse("#{interpolated['rpc_server']}")
        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        request.body = JSON.dump({
          "jsonrpc" => "2.0",
          "method" => "eth_sendTransaction",
          "params" => [
            {
              "to" => "#{contract}",
              "from" => "#{interpolated['wallet']}",
              "value" => "0x#{final_value.to_s(16)}",
              "data" => "0x83f818b4#{to_hex(max_gain(contract).to_i)}#{to_hex(interpolated['round'].to_i)}",
              "gasPrice" => "#{eth_gasPrice(internal)}"
            }
          ],
#          "gas" => "0x186a0",
          "id" => 1
        })

        req_options = {
          use_ssl: uri.scheme == "https",
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
          http.request(request)
        end

        log_curl_output(response.code,response.body)
      end

    end

    def twobears_check_order_by_id()

      hex_value = sprintf("%064x", interpolated['value'].to_i)
      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "jsonrpc" => "2.0",
        "id" => 1,
        "method" => "eth_call",
        "params" => [
          {
            "data" => "0x0e0578f5#{hex_value}",
            "to" => "0x78afc46df1d3eb5cff7044d288a453fe43e17310"
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
        if payload != memory['last_status']
          create_event payload: decode_2bears_content(payload)
        end
      else
        create_event payload: decode_2bears_content(payload)
      end
      memory['last_status'] = payload

    end

    def decode_2bears_content(data)

      event = {}
      power = (10 ** 18).to_i
      hex_string = data['result'].gsub(/^0x/, '')
      chunk_size = 64
      chunks = hex_string.scan(/.{1,#{chunk_size}}/)
      tokenin = decode_2bears_token(chunks[7])
      tokenout = decode_2bears_token(chunks[8])
      event['timestamp'] = chunks[0].to_i(16)
      event['commission'] = "#{chunks[1].to_i(16)/ power.to_i.to_f} #{tokenout}"
      event['value_in'] = "#{chunks[2].to_i(16) / power.to_i.to_f} #{tokenin}"
      event['price'] = "#{chunks[3].to_i(16) / power.to_i.to_f} #{tokenin}"
      event['value_out'] = "#{chunks[4].to_i(16) / power.to_i.to_f} #{tokenout}"
      event['exec_in'] = "#{chunks[5].to_i(16) / power.to_i.to_f} #{tokenin}"
      event['exec_out'] = "#{chunks[6].to_i(16) / power.to_i.to_f} #{tokenout}"
      event['token_in'] = tokenin
      event['token_out'] = tokenout
      event['owner'] = "0x#{chunks[9]}"
      event['order_type'] = (chunks[10].to_i(16) == 1) ? "Sell" : "Buy"
      event['order_status'] = (chunks[11].to_i(16) == 1) ? "Active" : "Executed"

      return event

    end

    def decode_2bears_token(token)
      case token
      when "0000000000000000000000000000000000000000000000000000000000000001"
        return "CLO"
      when "000000000000000000000000bf6c50889d3a620eb42c0f188b65ade90de958c4"
        return "BUSDT"
      else
        return "IDK"
      end

    end

    def get_tx_stats()
      all_miners = ['0xf34eaf6e2cf4744b5e29734295135c4213d59149', '0xed15b7b7b5dc81daae277a081b47a04c3a8bea1b' ,'0xd125b3b146d21d058edac7a5b5f7481a571e4c46', '0xe683de43ccfbef16424ecb577f288cf343dfbc5a', '0x0073cf1b9230cf3ee8cab1971b8dbef21ea7b595', '0x40b67778d97a7d15a519d907ed991948e8ea486c', '0x8845ee5cae61b807678415bb8a68773df9d48f8e', '0x52f0458c70af5cdeb555cad800add5f82c3e59f7', '0xd06bb917c099acf24d43552b5aa760aeef7cd4aa', '0xf35074bbd0a9aee46f4ea137971feec024ab704e', '0xd144e30a0571aaf0d0c050070ac435deba461fab', '0x8057c50c6d72f4399862fefbc8d3b8a8757cde57', '0xfbf679d6ed0cb9747e05e7e8ae06e890e6bf2b66', '0x11905bd0863ba579023f662d1935e39d0c671933', '0xe4f3cab1f11d5a917ac73c80927e64ee4b1a445a', '0xae83a3e136e6714e6c1e5483950936d7872fb999', '0x39ec1c88a7a7c1a575e8c8f42eff7630d9278179', '0xd6d27255eaef8c3fcb5433acb5494bf04cb5f2c3', '0x004730417cd2b1d19f6be2679906ded4fa8a64e2', '0x89308111f17a395b82f1e5a2824bd01fd13a53b5', '0x800f25eb68a06ff9671605bd450c29e80f593e0a', '0xa5d9018f6c99ec3230633c1187c5cb607c704ed8', '0xfe59743b65f2afec200ce279a289cb4a43eb7eeb', '0x811bad1a4041a9f6ed8fc2f4e9d421dc82626f81', '0xbd12b4511ec9fd1cf481d5643f307252ae6f55e2', '0x5f7661e493d4f1a318c02e9383568597e8a09b5a', '0xe0bac765ca88706a12e4f5a9c0e92dc823fe6293', '0x40c48b386e15981df5a10552cb97ee6d232c8547', '0x458ddc6a7e924554756f95715a53bf948560ee38', '0x3c6b9edb1f8ec6c85436b7cb384eb607489c732f', '0x2a1efdf9f09869a82e5e6b0f3736aabcb5381206', '0xf30a30315d5214e490458d0511595e42b3d917d0', '0x8c2fdc530815eb4267c8b12f10adafc4ca73484a', '0x254b0e1dee486908345e608da64afe35caa02a1c']
      shitty_wallets = ['0x7971d8defa89bf68ff4142b2bb1e1e3866927b36', '0x33344541086c709fe585caeabc83e5947e783333', '0xcbb8aaf930497c7bd0de6b19903410698e8adab4', '0xc352d245f25fec51ff15c77fc5bf767bf655276a', '0x9daa24510951bc0ac5d1e4f89de5efd89cc8e0b0', '0x941dab361e6d3f0b310f78c2c9eb6779608de0c3', '0x8877e6657f48aee236b47eb1c65be8e7a44f11f8', '0x1a146e329333919542cdb6d2d87de370275124c6', '0xf7d862d42976662d649cc356f4ca3854d595d53d', '0xd125b9d1415b77e0951d5b91dce3ce5d9e4375d0', '0xb94f03ad1b8ddddb82b08cd038b652cbfc47fbb4', '0x8832abcd7248ed2bd740d3eafdeb774ab8332623', '0x6dfb81b6945967e57052e4132a9ca328f8d12f7c', '0x11817fa65a9c2f68fc03bbbc9f2113d59b96908b']
      callosha_address = '0xb89fd29c048e974f9c3bc320c0b68651b434c159'
      slotmachine_address = '0x7777265dc7fd2a15a7f2e8d8ad87b3daec677777'
      twobears_address = '0x78afc46df1d3eb5cff7044d288a453fe43e17310'
      vipwarz_address = '0x2f48b8887d2d5d5b718c9f6516b44ba1c1bb8db1'
      internal = true
      tx_list = []
      burnt_ether = 0
      (interpolated['first_block']..interpolated['last_block']).each do |i|
        transactions = get_data(i.to_i,internal)
        gas_used = transactions['result']['gasUsed'].to_i(16)
        transactions['result']['transactions'].each do |tx|
          if !tx.empty?
            gas_price = tx['gasPrice'].to_i(16)
            fees = gas_price * gas_used.to_f / 10**18
            tx_list << tx
          end
          burnt_ether += fees
        end
      end
      top_tx = most_common_from(tx_list)
      top_count = tx_list.count { |hash| hash['from'] == top_tx }
      miners_count = tx_list.select { |hash| all_miners.include?(hash['from']) }
#      log "miners_count #{miners_count.count}"
      shitty_count = tx_list.select { |hash| shitty_wallets.include?(hash['from']) }
      callosha_count = tx_list.select { |hash| hash['to'] == callosha_address }
      twobears_count = tx_list.select { |hash| hash['to'] == twobears_address }
      vipwarz_count = tx_list.select { |hash| hash['to'] == vipwarz_address }
      slotmachine_count = tx_list.select { |hash| hash['to'] == slotmachine_address }
#      log "shitty_count #{shitty_count.count}"
      active = tx_list.map { |p| p['from'] }.uniq.count
#      log "top_count : #{top_count}"
#      log "total : #{tx_list.count}"
      create_event :payload => { 'total_tx' => "#{tx_list.count}", 'total_active' => "#{active}", 'burnt_clo' => "#{burnt_ether}", 'top_wallet': {'address' => "#{top_tx}", 'percentage' => "#{percentage(top_count.to_i,tx_list.count.to_i)}"}, 'shitty': {'address': 'shitty', 'shitty_percentage' => "#{percentage(shitty_count.count,tx_list.count.to_i)}"}, 'miners': {'address': "miners", 'percentage' => "#{percentage(miners_count.count,tx_list.count.to_i)}"}, 'callosha': {'address': callosha_address, 'percentage' => "#{percentage(callosha_count.count,tx_list.count.to_i)}"}, 'twobears': {'address': twobears_address, 'percentage' => "#{percentage(twobears_count.count,tx_list.count.to_i)}"}, 'vipwarz': {'address': vipwarz_address, 'percentage' => "#{percentage(vipwarz_count.count,tx_list.count.to_i)}"}, 'slotmachine': {'address': slotmachine_address, 'percentage' => "#{percentage(slotmachine_count.count,tx_list.count.to_i)}"}}

    end

    def get_data(x,internal=false)
      hexa_block = x.to_s(16)
      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "jsonrpc" => "2.0",
        "method" => "eth_getBlockByNumber",
        "params" => [
          "0x#{hexa_block}",
          true
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

      tx = JSON.parse(response.body)
      if internal == false
        timestamp = tx['result']['timestamp'].to_i(16)
        power = (10 ** 18).to_i
        if !tx['result']['transactions'].empty?
          tx['result']['transactions'].each do |transaction|
            if ( !transaction['from'].nil? && interpolated['wallet'].upcase.include?(transaction['from'].upcase) ) || ( !transaction['to'].nil? && interpolated['wallet_dest'].upcase.include?(transaction['to'].upcase) )
              if interpolated['filter_for_method_id'].empty? || interpolated['filter_for_method_id'].include?(transaction['input'][0, 10])
                transaction['blockNumber'] = transaction['blockNumber'].to_i(16)
                transaction['timestamp'] = timestamp
                receipt_data = get_tx_receipt(transaction['hash'])
                transaction['status'] = receipt_data['result']['status']
  #              transaction['input_converted_utf8'] = [transaction['input']].pack("H*")
                case transaction['input'][0, 10]
                when "0x"
                  transaction['call_type'] = 'Transfer'
                  transaction['symbol'] = "CLO"
                  transaction['value'] = "#{transaction['value'].to_i(16) / power.to_i.to_f}"
                when "0xb88a802f"
                  transaction['symbol'] = find_symbol(transaction['to'])
                when "0x6bd7a97a"
                  transaction['vesting_receiver'] = "0x#{transaction['input'][34, 40]}"
                  transaction['vesting_amount'] = "#{transaction['input'][74, 64].to_i(16) / power.to_i.to_f}"
                  transaction['vesting_symbol'] = "DIFF"
                when "0xa9059cbb"
                  transaction['symbol'] = find_symbol(transaction['to'])
  #                transaction['to'] = transaction['input'][10, 64]
                  transaction['to'] = "0x#{transaction['input'][34, 40]}"
                  transaction['value'] = "#{transaction['input'][74, 64].to_i(16) / power.to_i.to_f}"
#                else
#                  transaction['call_type'] = 'unknown'
                end
                if transaction['input'] != '0x'
                  hex_string = transaction['input'].dup
                  hex_string.slice!(0, 2)
                  # Convert hexadecimal string to bytes
                  bytes_string = [hex_string].pack("H*")
                  # Try to convert bytes to UTF-8 and check if it's readable
                  decoded_string = bytes_string.force_encoding("utf-8")
                  # Check if the conversion is successful without loss of information
                  if decoded_string.valid_encoding? && decoded_string.encode("utf-8", invalid: :replace, undef: :replace) == decoded_string
                    puts "The string is readable by a human: #{decoded_string}"
                    transaction['input_utf8'] = decoded_string
                  end
                end
                if !interpolated['sql_db'].empty?
                  if !transaction['call_type'].present?
                    transaction['call_type'] = function_finder(transaction['to'],transaction['input'][0, 10])
                  end
                  find_to = owner_finder(transaction['to'])
                  if !find_to.nil?
                    transaction['to_resolved'] = find_to
                  end
                  find_from = owner_finder(transaction['from'])
                  if !find_from.nil?
                    transaction['from_resolved'] = find_from
                  end
                end
#                log "#{transaction['input'][0, 10]} -> #{function_finder(transaction['to'],true,transaction['input'][0, 10])}"
                create_event payload: transaction
              end
            end
          end
        end
      else
        return tx
      end
    end

    def get_tx_by_address_with_filter()

	  if memory['previous_block'].blank? || !memory['previous_block'].present?
		x = interpolated['last_block'].to_i
        if interpolated['debug'] == 'true'
          log "previous_block in memory is missing or empty"
        end
	  else
        x = memory['previous_block'].to_i
        x = x + 1
        if interpolated['debug'] == 'true'
          log "previous_block in memory is #{memory['previous_block']} so next batch will be #{x}"
        end
	  end
      y = interpolated['last_block'].to_i

      while x <= y
        get_data(x).to_s
        if interpolated['debug'] == 'true'
          log "block #{x} is parsed"
        end
		memory['previous_block'] = x
        x = x + 1
      end

    end

    def unlock_wallet()
      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json;charset=UTF-8"
      request["Accept"] = "application/json, text/plain, /"
      request["Cache-Control"] = "no-cache"
      request.body = JSON.dump({
        "jsonrpc" => "2.0",
        "method" => "personal_unlockAccount",
        "params" => [
          "#{interpolated['wallet']}",
          "#{interpolated['wallet_password']}",
          15
        ],
        "id" => 67
      })

      req_options = {
        use_ssl: uri.scheme == "https",
      }

      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end

      log_curl_output(response.code,response.body)
      return response.body

    end

    def clo_sendtx()
      internal = true
      if interpolated['debug'] == 'true'
        log "unlocking the wallet"
      end
      response = JSON.parse(unlock_wallet())
      log "response -> #{response}"
      log "response result -> #{response['result']}"
      if response['result'] == true
        if interpolated['debug'] == 'true'
          log "the wallet is unlocked"
        end
        power_of_10 = 18
        final_value = interpolated['value'].to_i * 10**power_of_10
        uri = URI.parse("#{interpolated['rpc_server']}")
        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json; charset=UTF-8"
        request.body = JSON.dump({
          "jsonrpc" => "2.0",
          "method" => "eth_sendTransaction",
          "params" => [
            {
              "from" => "#{interpolated['wallet']}",
              "to" => "#{interpolated['wallet_dest']}",
              "value" => "0x#{final_value.to_s(16)}",
              "gasPrice" => "#{eth_gasPrice(internal)}"
            }
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

        if interpolated['emit_events'] == 'true'
          create_event payload: response.body
        end
      end
    end

    def start_cs_clo()
      internal = true
      if interpolated['debug'] == 'true'
        log "unlocking the wallet"
      end
      response = JSON.parse(unlock_wallet())
      log "response -> #{response}"
      log "response result -> #{response['result']}"
      if response['result'] == true
        if interpolated['debug'] == 'true'
          log "the wallet is unlocked"
        end
        power_of_10 = 18
        final_value = interpolated['value'].to_i * 10**power_of_10
        uri = URI.parse("#{interpolated['rpc_server']}")
        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        request.body = JSON.dump({
          "jsonrpc" => "2.0",
          "method" => "eth_sendTransaction",
          "params" => [
            {
              "from" => "#{interpolated['wallet']}",
              "to" => "0x08A7c8be47773546DC5E173d67B0c38AfFfa4b84",
              "data" => "0x5d8c85ef#{to_hex(interpolated['round'].to_i)}",
              "value" => "0x#{final_value.to_s(16)}",
              "gasPrice" => "#{eth_gasPrice(internal)}"
            }
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

        if interpolated['emit_events'] == 'true'
          create_event payload: response.body
        end
      end
    end

    def withdraw_cs_clo()
      internal = true
      if interpolated['debug'] == 'true'
        log "unlocking the wallet"
      end
      response = JSON.parse(unlock_wallet())
      log "response -> #{response}"
      log "response result -> #{response['result']}"
      if response['result'] == true
        if interpolated['debug'] == 'true'
          log "the wallet is unlocked"
        end
#        power_of_10 = 18
#        final_value = interpolated['value'].to_i * 10**power_of_10
        uri = URI.parse("#{interpolated['rpc_server']}")
        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        request.body = JSON.dump({
          "jsonrpc" => "2.0",
          "method" => "eth_sendTransaction",
          "params" => [
            {
              "from" => "#{interpolated['wallet']}",
              "to" => "0x08A7c8be47773546DC5E173d67B0c38AfFfa4b84",
              "data" => "0xcd948855",
              "gasPrice" => "#{eth_gasPrice(internal)}"
            }
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

        if interpolated['emit_events'] == 'true'
          create_event payload: response.body
        end
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
        if payload != memory['eth_getBlockByNumber']
          memory['eth_getBlockByNumber'] = payload
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
        if payload != memory['eth_getBlockByNumber']
          memory['eth_getBlockByNumber'] = payload
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
        if payload != memory['get_tokens_balance']
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
            last_status = memory['get_tokens_balance']
            payload.each do | token |
              found = false
              if interpolated['debug'] == 'true'
                log found
              end
              last_status.each do | tokenbis|
                if token == tokenbis
                  found = true
                end
                if interpolated['debug'] == 'true'
                  log found
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
          memory['get_tokens_balance'] = fixed_payload
        end
      else
        if payload != memory['get_tokens_balance']
          memory['get_tokens_balance']= fixed_payload
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

    def eth_gasPrice(internal=false)

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

      if internal == false
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
      else
        output = JSON.parse(response.body)

        return output['result']

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

    def get_balance(internal=false,address)

      uri = URI.parse("#{interpolated['rpc_server']}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "method" => "eth_getBalance",
        "params" => [
          "#{address}",
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

      power = (10 ** 18).to_i
      if internal == false
        if interpolated['changes_only'] == 'true'
          if payload != memory['get_balance']
            memory['get_balance'] = payload
            payload['name'] = "callisto"
            payload['symbol'] = "CLO"
            payload['result'] = payload['result'].to_i(16) / power.to_i.to_f
            create_event payload: payload
          end
        else
          if payload.to_s != memory['get_balance']
            memory['get_balance'] = payload
          end
          payload['result'] = payload['result'].to_i(16) / power.to_i.to_f
          create_event payload: payload
        end
      else
        payload['result'].to_i(16) / power.to_i.to_f
      end
    end

    def trigger_action

      case interpolated['type']
      when "get_balance"
        get_balance(false,interpolated['wallet'])
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
      when "clo_sendtx"
        clo_sendtx()
      when "start_cs_clo"
        start_cs_clo()
      when "withdraw_cs_clo"
        withdraw_cs_clo()
      when "get_tx_by_address_with_filter"
        get_tx_by_address_with_filter()
      when "get_tx_stats"
        get_tx_stats()
      when "callosha_slots"
        callosha_slots()
      when "2bears_check_order_by_id"
        twobears_check_order_by_id()
      when "get_abi_json"
        get_abi_json(interpolated['wallet'],false)
      else
        log "Error: type has an invalid value (#{type})"
      end
    end
  end
end
