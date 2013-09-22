require "virustotal"

describe Virustotal::API do
  it "should have a base_uri" do
    Virustotal::API.base_uri.should eql("https://www.virustotal.com/vtapi/v2")
  end
end

describe Virustotal::Client do
  it "should have options" do
    Virustotal::Client.options.class.should eql Hash
  end

  it "should have options with an api_key" do
    Virustotal::Client.options.keys.should include(:api_key)
  end
end