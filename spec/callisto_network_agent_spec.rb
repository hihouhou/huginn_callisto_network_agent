require 'rails_helper'
require 'huginn_agent/spec_helper'

describe Agents::CallistoNetworkAgent do
  before(:each) do
    @valid_options = Agents::CallistoNetworkAgent.new.default_options
    @checker = Agents::CallistoNetworkAgent.new(:name => "CallistoNetworkAgent", :options => @valid_options)
    @checker.user = users(:bob)
    @checker.save!
  end

  pending "add specs here"
end
