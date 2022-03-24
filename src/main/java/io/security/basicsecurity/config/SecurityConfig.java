package io.security.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @since       2022.01.05
 * @author      minam
 * @description security config
 **********************************************************************************************************************/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER"); // {noop} ? (PasswordEncoder에서 확인) - 패스워드 암호화 시 특정한 패스워드 알고리즘 방식/유형을 썼는지 prefix 형태로 적어야 한다. ({noop} = dkan
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/join/**").permitAll()
                .antMatchers("/thread").access("hasRole('ADMIN') or hasRole('SYS')")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .anyRequest().authenticated();

        http.formLogin()
                .defaultSuccessUrl ("/")
//                .failureUrl        ("/login?error=true")
                .usernameParameter ("username")
                .passwordParameter ("password")
                .loginProcessingUrl("/loginProcess")
                .successHandler(loginSuccessHandler())
//                .failureHandler(loginFailureHandler())
                .permitAll()
        ;
//
//        http.logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(logoutHandler())
//                .logoutSuccessHandler(logoutSuccessHandler())
//                .deleteCookies("JSESSIONID", "remember-me")
//        ;
//
        http.rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .alwaysRemember(Boolean.FALSE)
                .userDetailsService(userDetailsService)
        ;






        http.sessionManagement()
                .sessionFixation().none() // 세션 고정 보호를 위한 설정 (none,changesSessionId(기본), migrateSession, newSession)
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)// 동시성 제어를 위한 설정
                .maxSessionsPreventsLogin(true)
        ;










        http.exceptionHandling()
                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied"))
        ;

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_GLOBAL); // SecurityContext 모드 변경

    }

    private LogoutSuccessHandler logoutSuccessHandler() {
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.sendRedirect("/");
            }
        };
    }

    private LogoutHandler logoutHandler() {
        return new LogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                HttpSession session = request.getSession();
                if (session != null) {
                    session.invalidate();
                }
            }
        };
    }

    private AuthenticationSuccessHandler loginSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                System.out.println("authenticated:" + authentication.getName());

                RequestCache requestCache = new HttpSessionRequestCache();

                String redirectUrl = "/";
                SavedRequest savedRequest = requestCache.getRequest(request, response);

                if (savedRequest != null) {
                    redirectUrl = savedRequest.getRedirectUrl();
                }
                System.out.println(redirectUrl);

                response.sendRedirect(redirectUrl);
            }
        };
    }

    private AuthenticationFailureHandler loginFailureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                System.out.println("login fail:" + exception.getMessage());
                response.sendRedirect("/login?error");
            }
        };
    }
}

//@Configuration
//@EnableWebSecurity
//@Order(0)
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//        ;
//
//        http.sessionManagement()
//                .sessionFixation().changeSessionId();
//    }
//}
//
//@Configuration
//@Order(1)
//class SecurityConfig2 extends WebSecurityConfigurerAdapter {
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .anyRequest().permitAll()
//                .and()
//                .formLogin()
//        ;
//    }
//}