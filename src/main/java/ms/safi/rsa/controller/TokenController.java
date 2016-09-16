package ms.safi.rsa.controller;

import ms.safi.rsa.model.Token;
import ms.safi.rsa.securid.Generator;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class TokenController {

    @RequestMapping("/token")
    public String token(@Valid Token token) {
        System.out.println(token);
        String code = Generator.securid_compute_tokencode(token, Generator.currentTime());
        return code.substring(code.length() - token.getLength());
    }
}
