package hello.com.backend_2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    /**
     "scope": "profile email",
     "sid": "7942dce4-e889-40c7-b06d-b1780587e638",
     "email_verified": false,
     "name": "user firstname user lastname",
      --->  "preferred_username": "user",
     "given_name": "user firstname",
     "family_name": "user lastname",
     "email": "user@user.com"
     */

    @Value("${jwt.auth.converter.principleAttribute}")
    String principleAttribute;

    @Value("${jwt.auth.converter.resource-id}")
    String resourceID;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
           jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
           extractResourceRolesFromJwt(jwt).stream()
        ).collect(Collectors.toSet());
        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipleClaimName(jwt)
        );
    }

    private String getPrincipleClaimName(Jwt jwt){
        String claimName = JwtClaimNames.SUB;
        if(principleAttribute != null){
            claimName = principleAttribute;
        }
        return jwt.getClaim(claimName);
    }

    private Collection<? extends GrantedAuthority> extractResourceRolesFromJwt(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String>  resoureRoles;

        /* from jwt token from keycloak
         "resource_access": {
            "hello_user": {
              "roles": [
                "client_user"
              ]
    },
        */
        //first step
        if(jwt.getClaim("resource_access") == null){
            return Set.of();
        }
        resourceAccess = jwt.getClaim("resource_access");

        //second step
        if(resourceAccess.get(resourceID) == null){
            return Set.of();
        }
        resource = (Map<String, Object>) resourceAccess.get(resourceID);

        //third step extract roles

        resoureRoles = (Collection<String>) resource.get("roles");

        return resoureRoles.stream().map(role -> new SimpleGrantedAuthority("Role_"+ role)).collect(Collectors.toSet());
    }
}
