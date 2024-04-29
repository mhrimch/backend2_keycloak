package hello.com.backend_2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
@EnableMethodSecurity
public class DemoRestContoller{
    @GetMapping
    String sayHello(){
        return "Hello from Spring boot & Keycloak";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('user')")
    String sayHelloUser(){
        return "Hello from User";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    String sayHelloAdmin(){
        return "Hello from Admin";
    }
}
