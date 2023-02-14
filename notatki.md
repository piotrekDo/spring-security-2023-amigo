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

## JWT

Security oparte na JsonWebToken wykorzystuje filtry przechwytujące każde żądanie HTTP. Najpierw filtr autoryzacji sprawdza
czy żądanie zawiera token. Następnie filter deleguje zapytanie do ``UserDetailService`` ten z kolei sprawdza w bazie danych / 
pamięci albo LDAP informacje o użytkowniku i zwraca do filtra. Filtr porówna dane z tokena i te uzyskane z serwisu.
Jeżeli wszystko się zgadza filtr uaktualnia ``SecurityContextHolder``. Żądanie zostanie przekierowane do odpowiedniego
kontrolera. 

### Zależności
Potrzebujemy zależności do obsługi JWT, np.
```
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

### Filtr - JWT authentication filter

Do procesowania żądań potrzebny będzie JWT filter. Filtr musi być komponentem i w tym przypadku rozszerzać klasę 
``OncePerRequestFilter``. Następnie nadpisujemy metodę ``doFilterInternal``  
  
Deklarujemy zmienne do przechowywania authentication headera,  
nazwy użytkownika, może być email,  
jwt token.  
  
Sprawdzamy czy nagłówek Authentication deklarowny w pierwszej zmiennej nie jest nullem (czyli czy jest w ogóle zawarty
w żądaniu) oraz czy rozpoczyna się od *Bearer*. Jest to konwecja nazwenictwa tzw. bearer tokenów. Jeżeli nagłówek rozpoczyna 
się inaczej nie możemy go zidentyfikować jako JWT token. W przypadku kdy któryś warunek nie jest spełniony kończymy pracę
filtra i możemy przepuścić żądanie dalej poprzez metodę ``filterChain.doFilter``. W ten sposób nie wykonamy dalszej  logiki 
metody i nie ustawimy w kontekście Spring informacji o prawidłowym tokenie. Na tym etapie moglibyśmy także zakończyć filtrowanie
ale mogą istnieć dalsze mechanizmy obchodzenia się z nieprawidłowym tokenem.  
  
Bezpośrednio za warunkami poprawności nagłówka Authorization możemy przypisać wartość do samego tokena, na tym etapie mamy
już pewność co do poprawnośći nagłówka. Wyciągamy więc token z pomocą metody ``substring`` i przekazuemy wartość 7 co oznacza
długość wyrazu *Bearer* oraz spację.  
  
Następnie pobieramy nazwę użytkownika. W przykładzie posługujemy się klasą pomocniczą. 
```
import io.jsonwebtoken.Claims;


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
```
  
Uzyskany email / nazwę uzytkownika weryfikujemy w kolejnej instrukcji warunkowej poprzez sprawdzenie czy sam email nie jest
nullem oraz czy kontekst nie ma już przypisanego obiektu ``Authentication`` (czy jest on null). Wewnątrz logiki musmimy 
uzyskać informację na temat użytkownika z serwisu. ``loadUserByUserName``. Obiekt ten będzie potrzebny do utworzenia obiektu
``Authentication``, który chcemy umieścić w kontekście Spring.  
  
Musimy rónież sprawdzić czy sam token jest poprawny. Tutaj również posługujemy się metodą z klasy pomocniczej.
```
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    
        private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    
        public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
        public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
```
  
Jeżeli wszystko się powiodło, mamy obiekt ``userDetails`` oraz token jest prawidłowy możemy utworzyć w kontekście obiekt
``Authentication``. ``Authentication`` jest interfejsem, implementowanym przez klasę ``AbstractAuthenticationToken`` ta z kolei 
jest rozszerzana przez ``UsernamePasswordAuthenticationToken`` i to właśnie ten obiekt posłuży nam za implementację 
``Authentication``.
```
UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
SecurityContextHolder.getContext().setAuthentication(authToken);
```
  
Po wszystkim możemy przepuścić filtrowanie dalej ``filterChain.doFilter(request, response)``.

```
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;

    public JwtAuthFilter(UserDetailsService userDetailsService, JwtUtils jwtUtils) {
        this.userDetailsService = userDetailsService;
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String userEmail;
        final String jwtToken;

        if (authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request, response);
            return;
        }
        jwtToken = authHeader.substring(7);
        userEmail = jwtUtils.extractUsername(jwtToken);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

**Klasa pomocnicza**
```
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtUtils {

    public final String jwtSigningKey = "secret";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean hasClaim(String token, String claimName){
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(jwtSigningKey)
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails);
    }

    public String generateToken(UserDetails userDetails, Map<String, Object> claims) {
        return createToken(claims, userDetails);
    }

    private String createToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey).compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
}
```
  
### Rejestrowanie filtra w config

Nasz nowy filtr rejestrujemy z pomocą metody ``addFilterBefore`` wskazując naszą klasę oraz tę, przed która ma zostać wywoałana.


```
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
     SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

### UserDetailsService

UserDetailsService jest interfejsem dostarczającym sprngowi potrzebne metody. Musimy utworzyć jego implementację. Można 
to zrobić poprzez stworzenie klasy lub Beana. Jedyną metoda, którą musimy nadpisać jest ``loadUserByUsername```. Przykładowy bean
wykorzystujący zapisaną 'na sztywno' listę z użytkownikami zamiast bazy danych. 
```
    @Bean
    public UserDetailsService userDetailsService(){
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return APPLICATION_USERS.stream().filter(u -> u.getUsername().equals(email)).findFirst().orElseThrow();
            }
        };
    }
```

Następnie musimy zarejestrować nasz serwis jak poniżej. Dodajemy odpowiednią linjkę ustaiająca ``authenticationProvider``.
W metodzie zwracającej providera możemy ustawić szerg rzeczy jak serwis czy password encoder używany w ramach aplikacji. 
```
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.authenticationProvider(authenticationProvider());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
     AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        return authenticationProvider;
    }
    
    @Bean
    PasswordEncoder passwordEncoder() {
        return new  BCryptPasswordEncoder();
    }
```

## Ustawienia endpointów
