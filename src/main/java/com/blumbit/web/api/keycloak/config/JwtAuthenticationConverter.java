package com.blumbit.web.api.keycloak.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
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

// Al momento de obtener nuestros roles, Spring Security adiciona la palabra ROLE_ al respectivo nombre del rol
// Por tanto, si tenemos el nombre admin_role, Spring Security le agrega ROLE_, quedando de la siguiente manera: ROLE_admin_role
// Lo que hace que NO tengamos el acceso respectivo
// Asi que debemos convertir el nombre del Rol, y ponerlo en el formato de Spring Security
// Para ello, usaremos la interface Converter de Spriong Core para hacerlo

@Component
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    // Definimos dos variables para realizar la obtencion de los roles
    // que se encuentran dentro del Token JWT
    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAttribute;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Usamos el elemento GrantedAuthority para obtener el rol y convertirlo en un flujo(Stream)
        Collection<GrantedAuthority> authorities = Stream
                .concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
                .toList();
        return new JwtAuthenticationToken(jwt, authorities, getPrincipleName(jwt));
    }
    // Otros métodos
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {

        // Extraer los roles que se tienen en el token JWT
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        // Dentro la estructura del Token JWt generado, existe una sección llamada resource_access
        // la cual tiene precisamente los roles que necesitamos, para ello se reliza lo siguiente:
        // Si no existe el recurso solicitado, entonces NO damos el acceso
        if (jwt.getClaim("resource_access") == null) { return Set.of(); }
        // Caso contrario de existir el recurso solicitado...
        resourceAccess = jwt.getClaim("resource_access");
        // Si NO existe el cliente (client_id), tampoco concedemos el acceso
        if (resourceAccess.get(resourceId) == null) { return Set.of(); }
        // Caso contrario de existir el recurso solicitado...
        resource = (Map<String, Object>) resourceAccess.get(resourceId);
        // Similar caso, al verificar si tiene los roles
        if (resource.get("roles") == null) { return Set.of(); }
        // Caso contrario
        resourceRoles = (Collection<String>) resource.get("roles");
        // Una vez obtenido los roles, concatenamos con la palabra ROLE_ de Spring Security
        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role)))
                .collect(Collectors.toSet());
    }

    // Obtenemos el nombre del usuario que generó el Token
    private String getPrincipleName(Jwt jwt) {

        String claimName = JwtClaimNames.SUB;

        if (principleAttribute != null) {
            claimName = principleAttribute;
        }
        return jwt.getClaim(claimName);
    }
}
