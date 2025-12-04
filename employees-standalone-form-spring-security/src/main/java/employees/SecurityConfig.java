package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                        //sorrend számít!
                        //először a konkrétabb szabályok jönnek, aztán az általánosabbak
                        registry ->
                                registry.requestMatchers("/login").permitAll()
                                        .requestMatchers("/").hasRole("USER")//itt vigyázzunk, hogy ne legyen /**, mert akkor minden engedélyezve lesz a USER-nek
                                        .requestMatchers("/create-employee").hasRole("ADMIN")
                                        .anyRequest().denyAll()
                )
                .formLogin(Customizer.withDefaults())
                .logout(Customizer.withDefaults());
        return http.build();
    }
}
