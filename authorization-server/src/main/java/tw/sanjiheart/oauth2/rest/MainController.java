package tw.sanjiheart.oauth2.rest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

  @GetMapping("/login")
  String login() {
    return "login";
  }

  @GetMapping("/logout")
  String logout() {
    return "logout";
  }

}
