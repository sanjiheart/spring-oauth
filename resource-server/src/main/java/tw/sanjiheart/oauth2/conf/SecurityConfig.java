package tw.sanjiheart.oauth2.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain FilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests()
        .mvcMatchers("/gans/**")
        .hasAuthority("SCOPE_gan.read")
        .anyRequest()
        .authenticated()
        .and()
        .oauth2ResourceServer()
        .jwt();
    return http.build();
  }

}
