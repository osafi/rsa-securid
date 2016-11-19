package ms.safi.rsa.controller;

import ms.safi.rsa.model.Token;
import ms.safi.rsa.securid.Generator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class TokenController {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @RequestMapping("/token")
    public String token(@Valid Token token) {
        log.info("Received request for {}", token);
        String code = Generator.securid_compute_tokencode(token, Generator.currentTime());
        return code.substring(code.length() - token.getLength());
    }
}
