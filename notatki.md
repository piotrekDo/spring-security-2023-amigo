# Security 2023

W Spring 3 zmienia się podejście do Security. Nie możemy już korzystać z ``WebSecurityConfigurerAdapter``. Klasa ta 
nie istnieje już w pakiecie ``org.springframework.security.config.annotation.web.configuration`` i najnowsza wersja
Spring wymusza na nas implementację interfejsu ``SecurityFilterChain`` pochodzącego z ``org.springframework.security.web ``.  
  
Domyślnie po dodaniu zależnoścci do Security Spring automatycznie uruchami zabezpieczenia i wygenereuje hasło.  
``Using generated security password: 5b10b358-8898-4ccc-82fe-35e6e86a356d``  
Jest to ustawienie domyślne. Wówczas chcąc odwiedzić localhost zotaniemy przekierowni na stronę logowania dostarczoną 
przez Springa. Domyślnymi danymi będzi ``user``oraz wygenerowane hasło dostępne w logach. Aby się wylogować przechodzimy
pod endpoint ``/logout``.  
  
Spring przy uruchomieniu aplikacji będzie poszukiwał beana implementującego ``SecurityFilterChain``.
Domyślna konfiguracja wygląda następująco
```
@Configuration(proxyBeanMethods = false)
@ConditionalOnDefaultWebSecurity
static class SecurityFilterChainConfiguration {

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.formLogin();
        http.httpBasic();
        return http.build();
    }

}
```
``http.authorizeHttpRequests().anyRequest().authenticated();`` spring wymusza uwierzytelnienie do każdego zasobu  
``http.formLogin();`` podstawowoa strona logowania  
``http.httpBasic();`` rozwiązanie na wypadek, gdy strona logowania nie zadziała.


## Basic Authentication

Rozpoczynamy od utworzenia klasy konfiguracyjnej oznaczonej adnotacją ``@EnableWebSecurity`` jest to specjalny rodzaj
adnotacji konfiguracyjnej informującej Springa o istnieniu konfiguracji dla zabezpieczeń. Wewnątrz takiej klasy musimy
dostarczyć wspomnianego *Beana* SecurityFilterChain

```
@EnableWebSecurity
public class SecurityConfig {

    @Bean
     SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
        return http.build();
    }
}
```