package ms.safi.rsa.controller;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import ms.safi.rsa.model.Token;
import ms.safi.rsa.securid.Generator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class TokenController {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method = RequestMethod.GET, path = "/token", produces = "application/json")
    @ApiOperation(value = "getToken", nickname = "getToken")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Success", response = Token.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 500, message = "Failure")})
    public String token(@Valid Token token) {
        log.info("Received request for {}", token);
        String code = Generator.securid_compute_tokencode(token, Generator.currentTime());
        return code.substring(code.length() - token.getLength());
    }
}
