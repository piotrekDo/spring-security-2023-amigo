# Security 2023

W Spring 3 zmienia się podejście do Security. Nie możemy już korzystać z ``WebSecurityConfigurerAdapter``. Klasa ta 
nie istnieje już w pakiecie ``org.springframework.security.config.annotation.web.configuration`` i najnowsza wersja
Spring wymusza na nas implementację interfejsu ``SecurityFilterChain`` pochodzącego z ``org.springframework.security.web ``.  
  
