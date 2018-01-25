package com.example.cors;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.security.Principal;
import java.util.Arrays;

@SpringBootApplication
@RestController
public class CorsApplication {

	public static void main(String[] args) {
		SpringApplication.run(CorsApplication.class, args);
	}


	@GetMapping("/welcome")
	public String welcome() {
		return "welcome";
	}

	@RequestMapping("/user")
	public Principal user(Principal user) {
		return user;
	}


	@RequestMapping("/")
	public String index() {
		return "主页";
	}
//	这里说明一下，@EnableOAuth2Sso注解。如果WebSecurityConfigurerAdapter类上注释了@EnableOAuth2Sso注解，那么将会添加身份验证过滤器和身份验证入口。
//
//	如果只有一个@EnableOAuth2Sso注解没有编写在WebSecurityConfigurerAdapter上，那么它将会为所有路径启用安全，并且会在基于HTTP Basic认证的安全链之前被添加。
//	详见@EnableOAuth2Sso的注释。
	@Component
	@EnableOAuth2Sso // 实现基于OAuth2的单点登录，建议跟踪进代码阅读以下该注解的注释，很有用
	public static class SecurityConfiguration extends WebSecurityConfigurerAdapter {


		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.
					antMatcher("/**")
					// 所有请求都得经过认证和授权
					.authorizeRequests().anyRequest().authenticated()
					.antMatchers("/","/anon").permitAll()
					.and()
					// 这里之所以要禁用csrf，是为了方便。
					// 否则，退出链接必须要发送一个post请求，请求还得带csrf token
					// 那样我还得写一个界面，发送post请求
					.csrf().disable()
					// 退出的URL是/logout
					.logout().logoutUrl("/logout").permitAll()
					// 退出成功后，跳转到/路径。
					.logoutSuccessUrl("/");
//					.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
		}
	}

	@Bean
	public WebMvcConfigurer corsConfigurer() {
		return new WebMvcConfigurerAdapter() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**").allowedOrigins("http://127.0.0.1:8089")
						.allowedMethods("*").allowedHeaders("*")
						.allowCredentials(true)
						.exposedHeaders(HttpHeaders.SET_COOKIE).maxAge(3600L);
			}
		};
	}

//
	@Bean
	@Qualifier("myRestTemplate")
	public OAuth2RestOperations restTemplate(@Value("${security.oauth2.client.accessTokenUri}") String tokenUrl) {

		OAuth2RestTemplate template = new OAuth2RestTemplate(fullAccessresourceDetails(tokenUrl), new DefaultOAuth2ClientContext(
				new DefaultAccessTokenRequest()));
		template.setAccessTokenProvider(userAccessTokenProvider());
		return template;
	}

	@Bean
	public AccessTokenProvider userAccessTokenProvider() {
		ResourceOwnerPasswordAccessTokenProvider accessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider();
		return accessTokenProvider;
	}

	@Bean
	public OAuth2ProtectedResourceDetails fullAccessresourceDetails(@Value("${security.oauth2.client.accessTokenUri}") String tokenUrl) {
		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
		resource.setAccessTokenUri(tokenUrl);
		resource.setClientId("devglan-client");
		resource.setGrantType("password");
		resource.setScope(Arrays.asList(new String[]{"trust","read","write"}));
		resource.setUsername("Alex123");
		resource.setPassword("password");
		return resource;
	}



}
