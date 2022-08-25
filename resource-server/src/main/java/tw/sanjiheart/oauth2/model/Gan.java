package tw.sanjiheart.oauth2.model;

public class Gan {

  private String name;

  private String sex;

  private Integer age;

  public Gan() {}

  public Gan(String name, String sex, Integer age) {
    this.name = name;
    this.sex = sex;
    this.age = age;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getSex() {
    return sex;
  }

  public void setSex(String sex) {
    this.sex = sex;
  }

  public Integer getAge() {
    return age;
  }

  public void setAge(Integer age) {
    this.age = age;
  }

  @Override
  public String toString() {
    return "Gan [name=" + name + ", sex=" + sex + ", age=" + age + "]";
  }

}
