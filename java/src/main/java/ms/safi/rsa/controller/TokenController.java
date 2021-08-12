package ms.safi.rsa.controller;

import ms.safi.rsa.model.Token;
import ms.safi.rsa.securid.Generator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class TokenController {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method = RequestMethod.GET, path = "/token", produces = "application/json")
    public String token(@Valid @ModelAttribute Token token) {
        log.info("Received request for {}", token);
        String code = Generator.securid_compute_tokencode(token, Generator.currentTime());
        return code.substring(code.length() - token.getLength());
    }
}
