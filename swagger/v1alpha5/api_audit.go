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
     * @param "ProjectIds" (optional.String) -
     * @param "StartTime" (optional.String) -
     * @param "EndTime" (optional.String) -
     * @param "Actions" (optional.String) -
     * @param "ActorIds" (optional.String) -
     * @param "ActorEmails" (optional.String) -
     * @param "ActorTypes" (optional.String) -
     * @param "TargetIds" (optional.String) -
     * @param "TargetTypes" (optional.String) -
     * @param "TargetNames" (optional.String) -
     * @param "AssociateIds" (optional.String) -
     * @param "AssociateTypes" (optional.String) -
     * @param "AssociateNames" (optional.String) -
     * @param "Locations" (optional.String) -
     * @param "Statuses" (optional.String) -
     * @param "Surfaces" (optional.String) -
@return AuditLogsGetResponse
*/

type AuditApiGetAuditLogsOpts struct {
	ProjectIds     optional.String
	StartTime      optional.String
	EndTime        optional.String
	Actions        optional.String
	ActorIds       optional.String
	ActorEmails    optional.String
	ActorTypes     optional.String
	TargetIds      optional.String
	TargetTypes    optional.String
	TargetNames    optional.String
	AssociateIds   optional.String
	AssociateTypes optional.String
	AssociateNames optional.String
	Locations      optional.String
	Statuses       optional.String
	Surfaces       optional.String
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
		localVarQueryParams.Add("project_ids", parameterToString(localVarOptionals.ProjectIds.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.StartTime.IsSet() {
		localVarQueryParams.Add("start_time", parameterToString(localVarOptionals.StartTime.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.EndTime.IsSet() {
		localVarQueryParams.Add("end_time", parameterToString(localVarOptionals.EndTime.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Actions.IsSet() {
		localVarQueryParams.Add("actions", parameterToString(localVarOptionals.Actions.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.ActorIds.IsSet() {
		localVarQueryParams.Add("actor_ids", parameterToString(localVarOptionals.ActorIds.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.ActorEmails.IsSet() {
		localVarQueryParams.Add("actor_emails", parameterToString(localVarOptionals.ActorEmails.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.ActorTypes.IsSet() {
		localVarQueryParams.Add("actor_types", parameterToString(localVarOptionals.ActorTypes.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.TargetIds.IsSet() {
		localVarQueryParams.Add("target_ids", parameterToString(localVarOptionals.TargetIds.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.TargetTypes.IsSet() {
		localVarQueryParams.Add("target_types", parameterToString(localVarOptionals.TargetTypes.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.TargetNames.IsSet() {
		localVarQueryParams.Add("target_names", parameterToString(localVarOptionals.TargetNames.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.AssociateIds.IsSet() {
		localVarQueryParams.Add("associate_ids", parameterToString(localVarOptionals.AssociateIds.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.AssociateTypes.IsSet() {
		localVarQueryParams.Add("associate_types", parameterToString(localVarOptionals.AssociateTypes.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.AssociateNames.IsSet() {
		localVarQueryParams.Add("associate_names", parameterToString(localVarOptionals.AssociateNames.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Locations.IsSet() {
		localVarQueryParams.Add("locations", parameterToString(localVarOptionals.Locations.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Statuses.IsSet() {
		localVarQueryParams.Add("statuses", parameterToString(localVarOptionals.Statuses.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Surfaces.IsSet() {
		localVarQueryParams.Add("surfaces", parameterToString(localVarOptionals.Surfaces.Value(), ""))
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
