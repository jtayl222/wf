package com.example.demo;

import java.util.List;
import java.util.Map.Entry;
import javax.annotation.security.RolesAllowed;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.kie.server.api.marshalling.MarshallingFormat;
import org.kie.server.api.model.definition.ProcessDefinition;
import org.kie.server.client.KieServicesClient;
import org.kie.server.client.KieServicesConfiguration;
import org.kie.server.client.KieServicesFactory;
import org.kie.server.client.ProcessServicesClient;
import org.kie.server.client.QueryServicesClient;
import org.kie.server.client.UIServicesClient;
import org.kie.server.client.credentials.EnteredTokenCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.SortDefault;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/bpm")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class BPMController {
	
	private static final Logger logger = LoggerFactory.getLogger(BPMController.class);
    static final String serverUrl = "http://localhost:8080/kie-server/services/rest/server";
	@ResponseBody
	@CrossOrigin(origins = "http://localhost")
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

	public static KieServicesClient getKieServicesClient() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) authentication;
		KeycloakSecurityContext sc = (KeycloakSecurityContext) kat.getCredentials();
		String authToken = sc.getTokenString();
		EnteredTokenCredentialsProvider credentialsProvider = new EnteredTokenCredentialsProvider(authToken);
		// configuration
		KieServicesConfiguration conf = KieServicesFactory.newRestConfiguration(serverUrl, credentialsProvider);
		conf.setMarshallingFormat(MarshallingFormat.JSON);
		// get KIE client
		return KieServicesFactory.newKieServicesClient(conf);
	}

}
