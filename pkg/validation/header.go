package validation

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func validateHeaders(headers []options.Header) []string {
	msgs := []string{}
	names := make(map[string]struct{})

	for _, header := range headers {
		msgs = append(msgs, validateHeader(header, names)...)
	}
	return msgs
}

func validateHeader(header options.Header, names map[string]struct{}) []string {
	msgs := []string{}

	if header.Name == "" {
		msgs = append(msgs, "header has empty name: names are required for all headers")
	}

	if _, ok := names[header.Name]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple headers found with name %q: header names must be unique", header.Name))
	}
	names[header.Name] = struct{}{}

	for _, value := range header.Values {
		msgs = append(msgs,
			prefixValues(fmt.Sprintf("invalid header %q: invalid values: ", header.Name),
				validateHeaderValue(header.Name, value)...,
			)...,
		)
	}
	return msgs
}

func validateHeaderValue(name string, value options.HeaderValue) []string {
	switch {
	case value.SecretSource != nil && value.ClaimSource == nil && value.RequestSource == nil:
		return []string{validateSecretSource(*value.SecretSource)}
	case value.SecretSource == nil && value.ClaimSource != nil && value.RequestSource == nil:
		return validateHeaderValueClaimSource(*value.ClaimSource)
	case value.SecretSource == nil && value.ClaimSource == nil && value.RequestSource != nil:
		return validateHeaderValueRequestSource(*value.RequestSource)
	default:
		return []string{"header value has multiple entries: only one entry per value is allowed"}
	}
}

func validateHeaderValueClaimSource(claim options.ClaimSource) []string {
	msgs := []string{}

	if claim.Claim == "" {
		msgs = append(msgs, "claim should not be empty")
	}

	if claim.BasicAuthPassword != nil {
		msgs = append(msgs, prefixValues("invalid basicAuthPassword: ", validateSecretSource(*claim.BasicAuthPassword))...)
	}
	return msgs
}

func validateHeaderValueRequestSource(reqSource options.RequestSource) []string {
	if reqSource.RequestSourceAttr == "" {
		return []string{"requestSourceAttr should not be empty"}
	}

	expectedValues := []string{options.RequestSourceAttrProto, options.RequestSourceAttrHost, options.RequestSourceAttrURI}
	for _, v := range expectedValues {
		if reqSource.RequestSourceAttr == v {
			return []string{}
		}
	}
	return []string{fmt.Sprintf("requestSourceAttr should be one of %q", expectedValues)}
}
