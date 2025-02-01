/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/antihax/optional"
)

// Linger please
var (
	_ context.Context
)

type AuditApiService service

/*
AuditApiService Get audit logs belonging to the specified organization. User must be part of the organization.
 * @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param organizationId
 * @param optional nil or *AuditApiGetAuditLogsOpts - Optional Parameters:
     * @param "ProjectIds" (optional.Interface of []string) -
     * @param "StartTime" (optional.String) -
     * @param "EndTime" (optional.String) -
     * @param "Actions" (optional.Interface of []string) -
     * @param "ActorIds" (optional.Interface of []string) -
     * @param "ActorEmails" (optional.Interface of []string) -
     * @param "ActorTypes" (optional.Interface of []string) -
     * @param "TargetIds" (optional.Interface of []string) -
     * @param "TargetTypes" (optional.Interface of []string) -
     * @param "TargetNames" (optional.Interface of []string) -
     * @param "Locations" (optional.Interface of []string) -
     * @param "Results" (optional.Interface of []string) -
     * @param "Surfaces" (optional.Interface of []string) -
     * @param "Limit" (optional.String) -
     * @param "NextToken" (optional.String) -
     * @param "PrevToken" (optional.String) -
@return AuditLogsGetResponse
*/

type AuditApiGetAuditLogsOpts struct {
	ProjectIds  optional.Interface
	StartTime   optional.String
	EndTime     optional.String
	Actions     optional.Interface
	ActorIds    optional.Interface
	ActorEmails optional.Interface
	ActorTypes  optional.Interface
	TargetIds   optional.Interface
	TargetTypes optional.Interface
	TargetNames optional.Interface
	Locations   optional.Interface
	Results     optional.Interface
	Surfaces    optional.Interface
	Limit       optional.String
	NextToken   optional.String
	PrevToken   optional.String
}

func (a *AuditApiService) GetAuditLogs(ctx context.Context, organizationId string, localVarOptionals *AuditApiGetAuditLogsOpts) (AuditLogsGetResponse, *http.Response, error) {
	var (
		localVarHttpMethod  = strings.ToUpper("Get")
		localVarPostBody    interface{}
		localVarFileName    string
		localVarFileBytes   []byte
		localVarReturnValue AuditLogsGetResponse
	)

	// create path and map variables
	localVarPath := a.client.cfg.BasePath + "/organizations/{organization_id}/audit-logs"
	localVarPath = strings.Replace(localVarPath, "{"+"organization_id"+"}", fmt.Sprintf("%v", organizationId), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if localVarOptionals != nil && localVarOptionals.ProjectIds.IsSet() {
		localVarQueryParams.Add("project_ids", parameterToString(localVarOptionals.ProjectIds.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.StartTime.IsSet() {
		localVarQueryParams.Add("start_time", parameterToString(localVarOptionals.StartTime.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.EndTime.IsSet() {
		localVarQueryParams.Add("end_time", parameterToString(localVarOptionals.EndTime.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Actions.IsSet() {
		localVarQueryParams.Add("actions", parameterToString(localVarOptionals.Actions.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.ActorIds.IsSet() {
		localVarQueryParams.Add("actor_ids", parameterToString(localVarOptionals.ActorIds.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.ActorEmails.IsSet() {
		localVarQueryParams.Add("actor_emails", parameterToString(localVarOptionals.ActorEmails.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.ActorTypes.IsSet() {
		localVarQueryParams.Add("actor_types", parameterToString(localVarOptionals.ActorTypes.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.TargetIds.IsSet() {
		localVarQueryParams.Add("target_ids", parameterToString(localVarOptionals.TargetIds.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.TargetTypes.IsSet() {
		localVarQueryParams.Add("target_types", parameterToString(localVarOptionals.TargetTypes.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.TargetNames.IsSet() {
		localVarQueryParams.Add("target_names", parameterToString(localVarOptionals.TargetNames.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.Locations.IsSet() {
		localVarQueryParams.Add("locations", parameterToString(localVarOptionals.Locations.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.Results.IsSet() {
		localVarQueryParams.Add("results", parameterToString(localVarOptionals.Results.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.Surfaces.IsSet() {
		localVarQueryParams.Add("surfaces", parameterToString(localVarOptionals.Surfaces.Value(), "csv"))
	}
	if localVarOptionals != nil && localVarOptionals.Limit.IsSet() {
		localVarQueryParams.Add("limit", parameterToString(localVarOptionals.Limit.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.NextToken.IsSet() {
		localVarQueryParams.Add("next_token", parameterToString(localVarOptionals.NextToken.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.PrevToken.IsSet() {
		localVarQueryParams.Add("prev_token", parameterToString(localVarOptionals.PrevToken.Value(), ""))
	}
	// to determine the Content-Type header
	localVarHttpContentTypes := []string{}

	// set Content-Type header
	localVarHttpContentType := selectHeaderContentType(localVarHttpContentTypes)
	if localVarHttpContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHttpContentType
	}

	// to determine the Accept header
	localVarHttpHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHttpHeaderAccept := selectHeaderAccept(localVarHttpHeaderAccepts)
	if localVarHttpHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHttpHeaderAccept
	}
	r, err := a.client.prepareRequest(ctx, localVarPath, localVarHttpMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, localVarFileName, localVarFileBytes)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHttpResponse, err := a.client.callAPI(r)
	if err != nil || localVarHttpResponse == nil {
		return localVarReturnValue, localVarHttpResponse, err
	}

	localVarBody, err := ioutil.ReadAll(localVarHttpResponse.Body)
	localVarHttpResponse.Body.Close()
	if err != nil {
		return localVarReturnValue, localVarHttpResponse, err
	}

	if localVarHttpResponse.StatusCode < 300 {
		// If we succeed, return the data, otherwise pass on to decode error.
		err = a.client.decode(&localVarReturnValue, localVarBody, localVarHttpResponse.Header.Get("Content-Type"))
		if err == nil {
			return localVarReturnValue, localVarHttpResponse, err
		}
	}

	if localVarHttpResponse.StatusCode >= 300 {
		newErr := GenericSwaggerError{
			body:  localVarBody,
			error: localVarHttpResponse.Status,
		}
		if localVarHttpResponse.StatusCode == 200 {
			var v AuditLogsGetResponse
			err = a.client.decode(&v, localVarBody, localVarHttpResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHttpResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHttpResponse, newErr
		}
		if localVarHttpResponse.StatusCode == 400 {
			var v InlineResponse400
			err = a.client.decode(&v, localVarBody, localVarHttpResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHttpResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHttpResponse, newErr
		}
		if localVarHttpResponse.StatusCode == 401 {
			var v InlineResponse401
			err = a.client.decode(&v, localVarBody, localVarHttpResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHttpResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHttpResponse, newErr
		}
		if localVarHttpResponse.StatusCode == 403 {
			var v InlineResponse403
			err = a.client.decode(&v, localVarBody, localVarHttpResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHttpResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHttpResponse, newErr
		}
		if localVarHttpResponse.StatusCode == 500 {
			var v InlineResponse500
			err = a.client.decode(&v, localVarBody, localVarHttpResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHttpResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHttpResponse, newErr
		}
		return localVarReturnValue, localVarHttpResponse, newErr
	}

	return localVarReturnValue, localVarHttpResponse, nil
}
