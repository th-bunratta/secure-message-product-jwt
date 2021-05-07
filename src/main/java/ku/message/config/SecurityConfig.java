package ku.message.config;

import ku.message.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private AuthenticationService authenticationService;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(
                        "/home", "/signup", "/product",
                        "/css/**", "/js/**").permitAll()
                .anyRequest().authenticated();

        http.formLogin()
                .defaultSuccessUrl("/message", true)
                .and().logout();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(this.authenticationService);
//        auth.inMemoryAuthentication()
//                .withUser("usa")
//                .password(encoder().encode("usa"))
//                .roles("USER");
    }

    @Bean
    public PasswordEncoder encoder() {
        int strength = 14; // work factor of bcrypt
        return new BCryptPasswordEncoder(strength);
    }

}
