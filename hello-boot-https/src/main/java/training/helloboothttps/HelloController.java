package training.helloboothttps;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/hello")
public class HelloController {
    @RequestMapping
    public String hello() {
        return "Hello World! %s".formatted(LocalDateTime.now());
    }
}
