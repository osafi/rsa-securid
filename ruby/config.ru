require "json"

require "roda"

require_relative "rsa-auth"

class App < Roda
  route do |r|
    r.on "" do
      r.post do
        json = JSON.parse(request.body.read)
        token = Token.new(**json.transform_keys(&:to_sym))
        JSON.dump({ code: token.code })
      end
    end
  end
end

run App.freeze.app
