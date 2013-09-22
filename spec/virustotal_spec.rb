require "virustotal"

describe Virustotal::API do
  it "should have a base_uri" do
    Virustotal::API.base_uri.should eql("https://www.virustotal.com/vtapi/v2")
  end
end