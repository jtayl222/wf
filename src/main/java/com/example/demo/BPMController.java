package com.example.demo;

import java.util.List;

import javax.annotation.security.RolesAllowed;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.kie.server.api.marshalling.MarshallingFormat;
import org.kie.server.api.model.KieContainerResource;
import org.kie.server.api.model.KieServerInfo;
import org.kie.server.client.KieServicesClient;
import org.kie.server.client.KieServicesConfiguration;
import org.kie.server.client.KieServicesFactory;
import org.kie.server.client.UIServicesClient;
import org.kie.server.client.credentials.EnteredTokenCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
//@RequestMapping("/bpm")
//@CrossOrigin(origins = "*", allowedHeaders = "*")
public class BPMController {
	
	private static final Logger logger = LoggerFactory.getLogger(BPMController.class);
	static final String serverUrl = "http://localhost:8080/kie-server/services/rest/server";

	@RolesAllowed("client") 
	@RequestMapping("/") 
	public String index() { 
		System.out.println("===> index"); 
		return "KIE Server UI"; 
	}
	
	@ResponseBody
	@CrossOrigin(origins = "http://localhost")
	@RolesAllowed("client")
	@GetMapping("/postForm/{containerId}/{processId}")
	public String getFormResults(ModelMap model, @PathVariable("containerId") String containerId,
			@PathVariable("processId") String processId) {
		logger.debug("Looking for kickoff form for container {} and process id {}", containerId, processId);
		String form = getKieServicesClient().getServicesClient(UIServicesClient.class).renderProcessForm(containerId, processId,
						UIServicesClient.BOOTSTRAP_FORM_RENDERER);
		//String form = getKieServicesClient().getServicesClient().renderProcessForm(containerId, processId,
		//		UIServicesClient.BOOTSTRAP_FORM_RENDERER));
		return form;
	}
	
    @ResponseBody
    @CrossOrigin(origins = "http://localhost")
    @RolesAllowed("client")
    @GetMapping("/containers")
    public String getContainers(ModelMap model) {
        System.out.println("====> get containers");
        List<KieContainerResource> containers = getKieServicesClient().listContainers().getResult().getContainers();
        System.out.println("====> containers = " + containers);
        return containers != null ? containers.toString() : "empty result";
    }

    @ResponseBody
    @CrossOrigin(origins = "http://localhost")
//    @RolesAllowed("user")
    @GetMapping("/info")
    public String getServerInfo(ModelMap model) {
        System.out.println("====> get server info");
        KieServerInfo result = getKieServicesClient().getServerInfo().getResult();
        System.out.println("====> server info = " + result);
        return result != null ? result.toString() : "empty result";
    }

	public static KieServicesClient getKieServicesClient() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Authentication = " + authentication);
		KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) authentication;
		System.out.println("token = " + kat);
		KeycloakSecurityContext sc = (KeycloakSecurityContext) kat.getCredentials();
		String authToken = sc.getTokenString();
		System.out.println("authToken = " + authToken);
		EnteredTokenCredentialsProvider credentialsProvider = new EnteredTokenCredentialsProvider(authToken);
		System.out.println("credentialsProvider = " + credentialsProvider);
		// configuration
		KieServicesConfiguration conf = KieServicesFactory.newRestConfiguration(serverUrl, credentialsProvider);
		System.out.println("===> created KieServicesConfiguration");
		conf.setMarshallingFormat(MarshallingFormat.JSON);
		System.out.println("===> set marshalling format to JSON");
		// get KIE client
		return KieServicesFactory.newKieServicesClient(conf);
	}

}
