package tw.sanjiheart.oauth2.rest;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import tw.sanjiheart.oauth2.model.Gan;

@RestController
public class GanController {

  @Autowired
  private WebClient webClient;

  @GetMapping("/gans")
  public List<Gan> list(
      @RegisteredOAuth2AuthorizedClient("gan-authorization-code") OAuth2AuthorizedClient authorizedClient) {
    return this.webClient.get().uri("http://127.0.0.1:8090/gans")
        .attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
        .retrieve().bodyToMono(new ParameterizedTypeReference<List<Gan>>() {}).block();
  }

}
