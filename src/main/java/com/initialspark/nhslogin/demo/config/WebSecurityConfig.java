package com.initialspark.nhslogin.demo.config;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.JWSAlgorithm;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.service.impl.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.util.*;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${oidc.issueruri}")
    private String issuerUri;

    @Value("${oidc.clientid}")
    private String clientId;

    @Value("${oidc.scopes}")
    private String scopes;

    @Value("${oidc.redirecturi}")
    private String redirectUri;

    @Value("${oidc.keystorepath}")
    private String keystorePath;

    /**
     * This is the key ID of the key used to sign the client's outgoing requests. This key
     * must exist in the keystore configured above (kid)
     */
    @Value("${oidc.defaultkey}")
    private String signingKeyId;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/image/**", "/css/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()

                .addFilterBefore(configureOIDCFilter(),
                        AbstractPreAuthenticatedProcessingFilter.class)

                // This sets up the application to automatically request an OIDC login when needed
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/openid_connect_login"))
                .and()

                // This sets up the logout system
                .logout()
                .logoutSuccessUrl("/")
                .permitAll();
    }

    /**
     * Create and configure the MITREid Connect client filter
     *
     * @return
     * @throws Exception
     */
    @Bean
    public OIDCAuthenticationFilter configureOIDCFilter() throws Exception {

        OIDCAuthenticationFilter filter = new OIDCAuthenticationFilter();

        StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
        issuerService.setIssuer(issuerUri);
        filter.setIssuerService(issuerService);

        filter.setServerConfigurationService(new DynamicServerConfigurationService());

        StaticClientConfigurationService clientService = new StaticClientConfigurationService();
        RegisteredClient client = new RegisteredClient();

        client.setClientId(clientId);
        client.setScope(getScopes());

        // This tells the client to use a signed JWT to authenticate itself against token endpoint
        client.setTokenEndpointAuthMethod(AuthMethod.PRIVATE_KEY);
        client.setRedirectUris(ImmutableSet.of(redirectUri));
        clientService.setClients(ImmutableMap.of(issuerUri, client));
        filter.setClientConfigurationService(clientService);

        filter.setAuthRequestOptionsService(getStaticAuthRequestOptionsService());
        filter.setAuthRequestUrlBuilder(new PlainAuthRequestUrlBuilder());

        filter.setAuthenticationManager(authenticationManager());

        return filter;
    }

	private ImmutableSet<String> getScopes() {
		String[] scopesList = scopes.split(" ");
		return ImmutableSet.copyOf(scopesList);
	}

	private StaticAuthRequestOptionsService getStaticAuthRequestOptionsService() {
        //extra params required for auth request can be added here
        Map<String, String> extraParams = new HashMap<>();
        extraParams.put("vtr", "[\"P0.Cp.Cd\", \"P0.Cp.Ck\", \"P0.Cm\"]");

        StaticAuthRequestOptionsService options = new StaticAuthRequestOptionsService();
        options.setOptions(extraParams);
        return options;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(configureOIDCAuthenticationProvider());
    }

    /**
     * This creates the authentication provider that handles the OIDC login process
     * to create a spring Authentication object in the security context.
     *
     * @return
     */
    @Bean
    public AuthenticationProvider configureOIDCAuthenticationProvider() {
        return new OIDCAuthenticationProvider();
    }

    /**
     * This creates a component to fetch the public keys of the IdP
     */
    @Bean
    public JWKSetCacheService createValidatorCache() {
        return new JWKSetCacheService();
    }


    /**
     * This loads the public and private keys for this client from the
     * JWKS file, path configured above.
     *
     * @return
     */
    @Bean
    public JWKSetKeyStore createKeyStore() {
        //if in pem format keypair needs converting to jwks format
        JWKSetKeyStore keyStore = new JWKSetKeyStore();
        keyStore.setLocation(new ClassPathResource(keystorePath));
        return keyStore;
    }

    /**
     * This creates the services that signs the outgoing request and validates
     * the ID token's signature.
     *
     * @return
     * @throws Exception
     */
    @Bean
    public JWTSigningAndValidationService createSigningService() throws Exception {
        DefaultJWTSigningAndValidationService jwtSigningAndValidationService = new DefaultJWTSigningAndValidationService(createKeyStore());
        jwtSigningAndValidationService.setDefaultSignerKeyId(signingKeyId);
        jwtSigningAndValidationService.setDefaultSigningAlgorithmName(JWSAlgorithm.RS512.getName());
        return jwtSigningAndValidationService;
    }

}
