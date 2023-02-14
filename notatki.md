# Security 2023

W Spring 3 zmienia się podejście do Security. Nie możemy już korzystać z ``WebSecurityConfigurerAdapter``. Klasa ta 
nie istnieje już w pakiecie ``org.springframework.security.config.annotation.web.configuration`` i najnowsza wersja
Spring wymusza na nas implementację interfejsu ``SecurityFilterChain`` pochodzącego z ``org.springframework.security.web ``.  
  
Domyślnie po dodaniu zależnoścci do Security Spring automatycznie uruchami zabezpieczenia i wygenereuje hasło.  
``Using generated security password: 5b10b358-8898-4ccc-82fe-35e6e86a356d``  
Jest to ustawienie domyślne. Wówczas chcąc odwiedzić localhost zotaniemy przekierowni na stronę logowania dostarczoną 
przez Springa. Domyślnymi danymi będzi ``user``oraz wygenerowane hasło dostępne w logach. Aby się wylogować przechodzimy
pod endpoint ``/logout``.