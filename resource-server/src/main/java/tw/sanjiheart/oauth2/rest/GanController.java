package tw.sanjiheart.oauth2.rest;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Lists;

import tw.sanjiheart.oauth2.model.Gan;

@RestController
public class GanController {

  @GetMapping("/gans")
  public List<Gan> list() {
    return Lists.newArrayList(new Gan("HenGan", "Male", 32), new Gan("ChiaoGan", "Female", 78),
        new Gan("SuperGan", "Male", 87));
  }

}
