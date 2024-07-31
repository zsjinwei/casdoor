package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/casdoor/casdoor/object"
	"github.com/golang-jwt/jwt/v4"
)

func (c *RootController) ThirdPartyValidate() {
	service := c.Input().Get("service")
	if strings.ToLower(service) == "hasura" {
		c.hasuraValidate()
		return
	} else {
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		c.Ctx.Output.Body([]byte(fmt.Sprintf("Third party service(%s) is not supported.", service)))
		return
	}
}

func (c *RootController) hasuraValidate() {
	type HasuraRequest struct {
		Variables     map[string]interface{} `json:"variables"`
		OperationName string                 `json:"operationName"`
		Query         string                 `json:"query"`
	}

	type HasuraRequestBody struct {
		Headers map[string]string `json:"headers"`
		Request HasuraRequest     `json:"request"`
	}

	body := c.Ctx.Input.RequestBody
	hasuraRequest := HasuraRequestBody{}

	err := json.Unmarshal(body, &hasuraRequest)
	if err != nil {
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		c.Ctx.Output.Body([]byte("Invalid request body"))
		return
	}

	fmt.Printf("hasuraRequest: %v\n", hasuraRequest)

	tokenString := ""
	authorization := hasuraRequest.Headers["Authorization"]
	if authorization == "" {
		authorization = hasuraRequest.Headers["authorization"]
	}

	bearerTokens := strings.Split(authorization, " ")
	if len(bearerTokens) < 2 {
		fmt.Println("Bearer token format is invalid")
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	} else {
		tokenString = bearerTokens[1]
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		fmt.Printf("Error parsing unverified token: %v\n", err)
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		fmt.Printf("Error parsing jwt kid header: %v\n", err)
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	}

	certs, err := object.GetGlobalCerts()
	if err != nil {
		fmt.Printf("Error get cert: %v\n", err)
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	}

	var cert *object.Cert = nil
	for _, c := range certs {
		if c.Name == kid {
			cert = c
			break
		}
	}

	if cert == nil {
		fmt.Printf("Can not find cert: %s\n", kid)
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	}

	claims, err := object.ParseJwtToken(tokenString, cert)
	if err != nil {
		fmt.Printf("Error parsing token: %v\n", err)
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	}

	if claims.TokenType != "access-token" {
		fmt.Println("Token is not access token")
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
		return
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Failed to convert claims to MapClaims")
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
	}

	hasuraClaims, ok := mapClaims["https://hasura.io/jwt/claims"].(map[string]interface{})
	if !ok {
		fmt.Println("Failed to find hasura claims")
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Ctx.Output.Body([]byte("Unauthorized"))
	}

	// TODO: use casbin to validate graphql request permission
	// permissionId := c.Input().Get("permissionId")
	// if permissionId != "" {
	// 	permission, err := object.GetPermission(permissionId)
	// 	if err != nil {
	// 		fmt.Printf("Error get permission: %v\n", err)
	// 		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
	// 		c.Ctx.Output.Body([]byte("Unauthorized"))
	// 		return
	// 	}

	// 	result, err := object.Enforce(permission, []string{"", "", ""})
	// 	if err != nil {
	// 		fmt.Printf("Error enforce permission: %v\n", err)
	// 		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
	// 		c.Ctx.Output.Body([]byte("Unauthorized"))
	// 		return
	// 	}

	// 	if !result {
	// 		c.Data["json"] = map[string]string{
	// 			"X-Hasura-Role": "anonymous",
	// 		}
	// 		c.ServeJSON()
	// 		return
	// 	}
	// }

	hasuraResponse := make(map[string]string)
	hasuraResponse["X-Hasura-Application"] = hasuraClaims["x-hasura-application"].(string)
	hasuraResponse["X-Hasura-Client-Id"] = hasuraClaims["x-hasura-client-id"].(string)
	hasuraResponse["X-Hasura-Role"] = hasuraClaims["x-hasura-default-role"].(string)
	hasuraResponse["X-Hasura-Organization"] = hasuraClaims["x-hasura-organization"].(string)
	hasuraResponse["X-Hasura-Scope"] = hasuraClaims["x-hasura-scope"].(string)
	hasuraResponse["X-Hasura-Token-Type"] = hasuraClaims["x-hasura-token-type"].(string)
	hasuraResponse["X-Hasura-User-Id"] = hasuraClaims["x-hasura-user-id"].(string)
	hasuraResponse["X-Hasura-User-Tag"] = hasuraClaims["x-hasura-user-tag"].(string)
	hasuraResponse["Cache-Control"] = "max-age=600"

	c.Data["json"] = hasuraResponse
	c.ServeJSON()
}
