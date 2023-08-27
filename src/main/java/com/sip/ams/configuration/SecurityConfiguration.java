package com.sip.ams.configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.sql.DataSource;
@Configuration
@EnableWebSecurity
public class SecurityConfiguration  {
  
	@Autowired
	    private DataSource dataSource;
	 @Value("${spring.queries.users-query}")
	    private String usersQuery;
	    @Value("${spring.queries.roles-query}")
	    private String rolesQuery;
	
    @Bean
    public UserDetailsManager userDetailsManager () {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
        manager.setDataSource(dataSource);
        manager.setUsersByUsernameQuery(usersQuery);
        manager.setAuthoritiesByUsernameQuery(rolesQuery);
        return manager;
    }
    @Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}
 

		@Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests((authz) -> authz
                
                .antMatchers("/").permitAll() // accès pour tous users
                .antMatchers("/login").permitAll() // accès pour tous users
                .antMatchers("/registration").permitAll() // accès pour tous users
                .antMatchers("/role/**").permitAll()
                //.antMatchers("/accounts/**").permitAll()
                .antMatchers("/provider/**").hasAnyAuthority("ADMIN", "SUPERADMIN")
                .antMatchers("/article/**").hasAnyAuthority("USER", "ADMIN","SUPERADMIN").anyRequest()

                .authenticated()
                )
                .csrf((csrf)->csrf.disable()
                )
                .formLogin((formLogin)->formLogin // l'accès de fait via un formulaire
                
                .loginPage("/login").failureUrl("/login?error=true") // fixer la page login
                
                .defaultSuccessUrl("/home") // page d'accueil après login avec succès
                .usernameParameter("email") // paramètres d'authentifications login et password
                .passwordParameter("password")
                )
                .logout((logout)->logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // route de deconnexion ici /logut
                .logoutSuccessUrl("/login")
                )
                .exceptionHandling((exceptionHandling)->exceptionHandling // une fois deconnecté redirection vers login
                
                .accessDeniedPage("/403")
                ); 
                return http.build();
    }

   // laisser l'accès aux ressources
    
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
    }

}


