package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
//method-oknál megvizsgálja, hogy az adott felhsználónak van-e az adott metódus meghívásához joga
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    //lehet több security fitler chain
    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/login", "/", "/employees", "/create-employee","/logout","/default-ui-css") //ezekre az útvonalakra érvényes ez a security filter chain
                .authorizeHttpRequests(
                        //sorrend számít!
                        //először a konkrétabb szabályok jönnek, aztán az általánosabbak
                        registry ->
                                registry.requestMatchers("/login").permitAll()
                                        //egy kis sérülékenység: minden felhasználó eléri az összes alkalmazás funkciót
                                        //hogy lehet ezt a hibát kivédeni?
                                        //írjunk rá automatizált teszteket, és ellenőrizzük, hogy a megfelelő szerepkörrel csak a megfelelő funkciók érhetők el
                                        //.requestMatchers("/**").hasRole("USER")//itt vigyázzunk, hogy ne legyen /**, mert akkor minden engedélyezve lesz a USER-nek
                                        .requestMatchers("/", "/employees").hasRole("USER")//itt vigyázzunk, hogy ne legyen /**, mert akkor minden engedélyezve lesz a USER-nek
                                        .requestMatchers("/create-employee").hasRole("ADMIN")
                                        .anyRequest().denyAll()
                )
                //turn this off and set username to this:
                //<!-- <script src="http://127.0.0.1:5500/server/hello.js"></script> -->
                .headers(headers -> headers.contentSecurityPolicy(policy -> policy.policyDirectives("script-src 'self'")))
                .formLogin(Customizer.withDefaults())
                .logout(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain actuatorFitlerChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/actuator/**")
                .authorizeHttpRequests(
                        registry ->
                                registry.anyRequest().hasRole("ADMIN")
                )
                .headers(headers -> headers.contentSecurityPolicy(policy -> policy.policyDirectives("script-src 'self'")))
                .formLogin(Customizer.withDefaults())
                .logout(Customizer.withDefaults());
        return http.build();
    }


}
