// A subset of Google's Admin SDK Reports API discovery document (revision 20261111): activities.list and the
// Activity fields this emulator fills, as Google publishes them, with activities.watch, channels.stop and the Channel
// schema from revision 20261117. Every list parameter is kept so that clients built
// from the document accept them; the route refuses the ones it does not model.
const document = {
  kind: "discovery#restDescription",
  discoveryVersion: "v1",
  id: "admin:reports_v1",
  name: "admin",
  canonicalName: "reports",
  version: "reports_v1",
  revision: "20261111",
  title: "Admin SDK API",
  description:
    "Admin SDK lets administrators of enterprise domains to view and manage resources like user, groups etc. It also provides audit and usage reports of domain.",
  ownerDomain: "google.com",
  ownerName: "Google",
  documentationLink: "https://developers.google.com/workspace/admin/",
  protocol: "rest",
  parameters: {
    "$.xgafv": {
      type: "string",
      enum: ["1", "2"],
      description: "V1 error format.",
      enumDescriptions: ["v1 error format", "v2 error format"],
      location: "query",
    },
    callback: {
      type: "string",
      description: "JSONP",
      location: "query",
    },
    key: {
      type: "string",
      location: "query",
      description:
        "API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.",
    },
    prettyPrint: {
      description: "Returns response with indentations and line breaks.",
      type: "boolean",
      default: "true",
      location: "query",
    },
    access_token: {
      location: "query",
      type: "string",
      description: "OAuth access token.",
    },
    oauth_token: {
      location: "query",
      description: "OAuth 2.0 token for the current user.",
      type: "string",
    },
    quotaUser: {
      description:
        "Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.",
      location: "query",
      type: "string",
    },
    upload_protocol: {
      description: 'Upload protocol for media (e.g. "raw", "multipart").',
      location: "query",
      type: "string",
    },
    fields: {
      description: "Selector specifying which fields to include in a partial response.",
      location: "query",
      type: "string",
    },
    alt: {
      description: "Data format for response.",
      type: "string",
      enum: ["json", "media", "proto"],
      location: "query",
      default: "json",
      enumDescriptions: [
        "Responses with Content-Type of application/json",
        "Media download with context-dependent Content-Type",
        "Responses with Content-Type of application/x-protobuf",
      ],
    },
    uploadType: {
      type: "string",
      description: 'Legacy upload protocol for media (e.g. "media", "multipart").',
      location: "query",
    },
  },
  auth: {
    oauth2: {
      scopes: {
        "https://www.googleapis.com/auth/admin.reports.audit.readonly": {
          description: "View audit reports for your Google Workspace domain",
        },
      },
    },
  },
  schemas: {
    Channel: {
      properties: {
        resourceUri: { description: "A version-specific identifier for the watched resource.", type: "string" },
        token: {
          description:
            "An arbitrary string delivered to the target address with each notification delivered over this channel. Optional.",
          type: "string",
        },
        kind: {
          default: "api#channel",
          type: "string",
          description:
            'Identifies this as a notification channel used to watch for changes to a resource, which is "`api#channel`".',
        },
        payload: {
          description:
            "A Boolean value to indicate whether payload is wanted. A payload is data that is sent in the body of an HTTP POST, PUT, or PATCH message and contains important information about the request. Optional.",
          type: "boolean",
        },
        id: { description: "A UUID or similar unique string that identifies this channel.", type: "string" },
        params: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "Additional parameters controlling delivery channel behavior. Optional.",
        },
        type: {
          type: "string",
          description: 'The type of delivery mechanism used for this channel. The value should be set to `"web_hook"`.',
        },
        resourceId: {
          description:
            "An opaque ID that identifies the resource being watched on this channel. Stable across different API versions.",
          type: "string",
        },
        expiration: {
          type: "string",
          description:
            "Date and time of notification channel expiration, expressed as a Unix timestamp, in milliseconds. Optional.",
          format: "int64",
        },
        address: { description: "The address where notifications are delivered for this channel.", type: "string" },
      },
      description: "A notification channel used to watch for resource changes.",
      type: "object",
      id: "Channel",
    },
    Activities: {
      properties: {
        etag: {
          description: "ETag of the resource.",
          type: "string",
        },
        items: {
          description: "Each activity record in the response.",
          type: "array",
          items: {
            $ref: "Activity",
          },
        },
        nextPageToken: {
          description:
            "Token for retrieving the follow-on next page of the report. The `nextPageToken` value is used in the request's `pageToken` query string.",
          type: "string",
        },
        kind: {
          type: "string",
          default: "admin#reports#activities",
          description: "The type of API resource. For an activity report, the value is `reports#activities`.",
        },
      },
      id: "Activities",
      description: "JSON template for a collection of activities.",
      type: "object",
    },
    Activity: {
      id: "Activity",
      properties: {
        kind: {
          type: "string",
          default: "admin#reports#activity",
          description: "The type of API resource. For an activity report, the value is `audit#activity`.",
        },
        id: {
          properties: {
            applicationName: {
              description:
                "Application name to which the event belongs. For possible values see the list of applications above in `applicationName`.",
              type: "string",
            },
            time: {
              description: "Time of occurrence of the activity. This is in UNIX epoch time in seconds.",
              type: "string",
              format: "date-time",
            },
            customerId: {
              description: "The unique identifier for a Google Workspace account.",
              type: "string",
            },
            uniqueQualifier: {
              type: "string",
              format: "int64",
              description: "Unique qualifier if multiple events have the same time.",
            },
          },
          type: "object",
          description: "Unique identifier for each activity record.",
        },
        etag: {
          description: "ETag of the entry.",
          type: "string",
        },
        actor: {
          type: "object",
          properties: {
            email: {
              description:
                "The primary email address of the actor. May be absent if there is no email address associated with the actor.",
              type: "string",
            },
            profileId: {
              description:
                "The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID.",
              type: "string",
            },
            callerType: {
              description: "The type of actor.",
              type: "string",
            },
            applicationInfo: {
              properties: {
                oauthClientId: {
                  description: "OAuth client id of the third party application used to perform the action.",
                  type: "string",
                },
                applicationName: {
                  description: "Name of the application used to perform the action.",
                  type: "string",
                },
              },
              description: "Details of the application that was the actor for the activity.",
              type: "object",
            },
          },
          description: "User doing the action.",
        },
        ownerDomain: {
          type: "string",
          description:
            "This is the domain that is affected by the report's event. For example domain of Admin console or the Drive application's document owner.",
        },
        ipAddress: {
          description:
            "IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6.",
          type: "string",
        },
        events: {
          items: {
            type: "object",
            properties: {
              type: {
                type: "string",
                description:
                  "Type of event. The Google Workspace service or feature that an administrator changes is identified in the `type` property which identifies an event using the `eventName` property. For a full list of the API's `type` categories, see the list of event names for various applications above in `applicationName`.",
              },
              name: {
                type: "string",
                description:
                  "Name of the event. This is the specific name of the activity reported by the API. And each `eventName` is related to a specific Google Workspace service or feature which the API organizes into types of events. For `eventName` request parameters in general: - If no `eventName` is given, the report returns all possible instances of an `eventName`. - When you request an `eventName`, the API's response returns all activities which contain that `eventName`. For more information about `eventName` properties, see the list of event names for various applications above in `applicationName`.",
              },
              parameters: {
                description:
                  "Parameter value pairs for various applications. For more information about `eventName` parameters, see the list of event names for various applications above in `applicationName`.",
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: {
                      description: "The name of the parameter.",
                      type: "string",
                    },
                    value: {
                      description: "String value of the parameter.",
                      type: "string",
                    },
                    multiValue: {
                      description: "String values of the parameter.",
                      items: {
                        type: "string",
                      },
                      type: "array",
                    },
                    boolValue: {
                      description: "Boolean value of the parameter.",
                      type: "boolean",
                    },
                    intValue: {
                      description: "Integer value of the parameter.",
                      format: "int64",
                      type: "string",
                    },
                  },
                },
              },
            },
          },
          description: "Activity events in the report.",
          type: "array",
        },
      },
      description: "JSON template for the activity resource.",
      type: "object",
    },
  },
  resources: {
    activities: {
      methods: {
        list: {
          parameterOrder: ["userKey", "applicationName"],
          path: "admin/reports/v1/activity/users/{userKey}/applications/{applicationName}",
          flatPath: "admin/reports/v1/activity/users/{userKey}/applications/{applicationName}",
          scopes: ["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
          id: "reports.activities.list",
          description:
            "Retrieves a list of activities for a specific customer's account and application such as the Admin console application or the Google Drive application. For more information, see the guides for administrator and Google Drive activity reports. For more information about the activity report's parameters, see the activity parameters reference guides. ",
          httpMethod: "GET",
          response: {
            $ref: "Activities",
          },
          parameters: {
            agentInfoFilter: {
              description:
                'Optional. Filters on agent info fields in the activity. This filter gets applied in conjunction(AND) with other filters. Example: "agentInfoFilter=agentId=\\"agent-id\\" AND agentName=\\"agent-name\\" AND agentOwnerEmail=\\"agent-owner-email\\""',
              type: "string",
              location: "query",
            },
            applicationInfoFilter: {
              location: "query",
              description:
                'Optional. Used to filter on the `oAuthClientId` field present in [`ApplicationInfo`](#applicationinfo) message. **Usage** ``` GET...&applicationInfoFilter=oAuthClientId="clientId" GET...&applicationInfoFilter=oAuthClientId=%22clientId%22 ```',
              type: "string",
            },
            endTime: {
              pattern:
                "(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.(\\d+))?(?:(Z)|([-+])(\\d\\d):(\\d\\d))",
              description:
                "Sets the end of the range of time shown in the report. The date is in the RFC 3339 format, for example 2010-10-28T10:26:35.000Z. The default value is the approximate time of the API request. An API report has three basic time concepts: - *Date of the API's request for a report*: When the API created and retrieved the report. - *Report's start time*: The beginning of the timespan shown in the report. The `startTime` must be before the `endTime` (if specified) and the current time when the request is made, or the API returns an error. - *Report's end time*: The end of the timespan shown in the report. For example, the timespan of events summarized in a report can start in April and end in May. The report itself can be requested in August. If the `endTime` is not specified, the report returns all activities from the `startTime` until the current time or the most recent 180 days if the `startTime` is more than 180 days in the past. For Gmail requests, `startTime` and `endTime` must be provided and the difference must not be greater than 30 days.",
              location: "query",
              type: "string",
            },
            networkInfoFilter: {
              description:
                'Optional. Used to filter on the `regionCode` field present in [`NetworkInfo`](#networkinfo) message. **Usage** ``` GET...&networkInfoFilter=regionCode="IN" GET...&networkInfoFilter=regionCode=%22IN%22 ```',
              type: "string",
              location: "query",
            },
            includeSensitiveData: {
              location: "query",
              description:
                "Optional. When set to `true`, this field allows sensitive user-generated content to be included in the returned audit logs. This parameter is supported only for Rules (DLP), Chat and Workspace Studio applications; using it with any other application will result in a permission error.",
              type: "boolean",
            },
            orgUnitID: {
              description:
                "ID of the organizational unit to report on. Activity records will be shown only for users who belong to the specified organizational unit. Data before Dec 17, 2018 doesn't appear in the filtered results.",
              type: "string",
              location: "query",
              default: "",
              pattern: "(id:[a-z0-9]+)",
            },
            statusFilter: {
              location: "query",
              type: "string",
              description:
                'Optional. Used to filter on the `statusCode` field present in [`Status`](#status) message. **Usage** ``` GET...&statusFilter=statusCode="200" GET...&statusFilter=statusCode=%22200%22 ```',
            },
            deviceFilter: {
              location: "query",
              description:
                'Optional. Used to filter on the fields present in [`UserDeviceInfo`](#userdeviceinfo) message like `deviceId`, `deviceType`, and `deviceOsVersion`. **Usage** ``` GET...&deviceFilter=deviceId="123" GET...&deviceFilter=deviceType="ANDROID" GET...&deviceFilter=deviceOsVersion="14.0" ```',
              type: "string",
            },
            actorIpAddress: {
              description:
                "The Internet Protocol (IP) Address of host where the event was performed. This is an additional way to filter a report's summary using the IP address of the user whose activity is being reported. This IP address may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. This parameter supports both IPv4 and IPv6 address versions.",
              location: "query",
              type: "string",
            },
            customerId: {
              description: "The unique ID of the customer to retrieve data for.",
              pattern: "C.+|my_customer",
              location: "query",
              type: "string",
            },
            filters: {
              location: "query",
              type: "string",
              description:
                "The `filters` query string is a comma-separated list composed of event parameters manipulated by relational operators. Event parameters are in the form `{parameter1 name}{relational operator}{parameter1 value},{parameter2 name}{relational operator}{parameter2 value},...` These event parameters are associated with a specific `eventName`. An empty report is returned if the request's parameter doesn't belong to the `eventName`. For more information about the available `eventName` fields for each application and their associated parameters, go to the [ApplicationName](#applicationname) table, then click through to the Activity Events page in the Appendix for the application you want. In the following Drive activity examples, the returned list consists of all `edit` events where the `doc_id` parameter value matches the conditions defined by the relational operator. In the first example, the request returns all edited documents with a `doc_id` value equal to `12345`. In the second example, the report returns any edited documents where the `doc_id` value is not equal to `98765`. The `<>` operator is URL-encoded in the request's query string (`%3C%3E`): ``` GET...&eventName=edit&filters=doc_id==12345 GET...&eventName=edit&filters=doc_id%3C%3E98765 ``` A `filters` query supports these relational operators: * `==`: 'equal to'. * `<>`: 'not equal to'. Must be URL-encoded (%3C%3E). * `<`: 'less than'. Must be URL-encoded (%3C). * `<=`: 'less than or equal to'. Must be URL-encoded (%3C=). * `>`: 'greater than'. Must be URL-encoded (%3E). * `>=`: 'greater than or equal to'. Must be URL-encoded (%3E=). **Note:** The API doesn't accept multiple values of the same parameter. If a parameter is supplied more than once in the API request, the API only accepts the last value of that parameter. In addition, if an invalid parameter is supplied in the API request, the API ignores that parameter and returns the response corresponding to the remaining valid parameters. If no parameters are requested, all parameters are returned.",
              pattern: "(.+[<,<=,==,>=,>,<>].+,)*(.+[<,<=,==,>=,>,<>].+)",
            },
            groupIdFilter: {
              pattern: "(id:[a-z0-9]+(,id:[a-z0-9]+)*)",
              description:
                'Comma separated group ids (obfuscated) on which user activities are filtered, i.e. the response will contain activities for only those users that are a part of at least one of the group ids mentioned here. Format: "id:abc123,id:xyz456" *Important:* To filter by groups, you must explicitly add the groups to your filtering groups allowlist. For more information about adding groups to filtering groups allowlist, see [Filter results by Google Group](https://support.google.com/a/answer/11482175)',
              type: "string",
              location: "query",
            },
            pageToken: {
              description:
                "The token to specify next page. A report with multiple pages has a `nextPageToken` property in the response. In your follow-on request getting the next page of the report, enter the `nextPageToken` value in the `pageToken` query string.",
              type: "string",
              location: "query",
            },
            userKey: {
              location: "path",
              description:
                "Represents the profile ID or the user email for which the data should be filtered. Can be `all` for all information, or `userKey` for a user's unique Google Workspace profile ID or their primary email address. Must not be a deleted user. For a deleted user, call `users.list` in Directory API with `showDeleted=true`, then use the returned `ID` as the `userKey`.",
              type: "string",
              required: true,
            },
            resourceDetailsFilter: {
              location: "query",
              type: "string",
              description:
                'Optional. The `resourceDetailsFilter` query string is an AND separated list composed of [Resource Details](#resourcedetails) fields manipulated by relational operators. Resource Details Filters are in the form `{resourceDetails.field1}{relational operator}{field1 value} AND {resourceDetails.field2}{relational operator}{field2 value}...` All the inner fields are traversed using the `.` operator, as shown in the following example: ``` resourceDetails.id = "resourceId" AND resourceDetails.appliedLabels.id = "appliedLabelId" AND resourceDetails.appliedLabels.fieldValue.id = "fieldValueId" ``` `resourceDetailsFilter` query supports these relational operators: * `=`: \'equal to\'. * `!=`: \'not equal to\'. * `:`: \'exists\'. This is used for filtering on repeated fields. [`FieldValue`](#fieldvalue) types that are repeated in nature uses `exists` operator for filtering. The following [`FieldValue`](#fieldvalue) types are repeated: * [`TextListValue`](#textlistvalue) * [`SelectionListValue`](#selectionlistvalue) * [`UserListValue`](#userlistvalue) For example, in the following filter, [`SelectionListValue`](#selectionlistvalue), is a repeated field. The filter checks whether [`SelectionListValue`](#selectionlistvalue) contains `selection_id`: ``` resourceDetails.id = "resourceId" AND resourceDetails.appliedLabels.id = "appliedLabelId" AND resourceDetails.appliedLabels.fieldValue.id = "fieldValueId" AND resourceDetails.appliedLabels.fieldValue.type = "SELECTION_LIST_VALUE" AND resourceDetails.appliedLabels.fieldValue.selectionListValue.id: "id" ``` **Usage** ``` GET...&resourceDetailsFilter=resourceDetails.id = "resourceId" AND resourceDetails.appliedLabels.id = "appliedLabelId" GET...&resourceDetailsFilter=resourceDetails.id=%22resourceId%22%20AND%20resourceDetails.appliedLabels.id=%22appliedLabelId%22 ``` **Note the following**: * You must URL encode the query string before sending the request. * The API supports a maximum of 5 fields separated by the AND operator. - When filtering on deeper levels (e.g., [`AppliedLabel`](#appliedlabel), [`FieldValue`](#fieldvalue)), the IDs of all preceding levels in the hierarchy must be included in the filter. For example: Filtering on [`FieldValue`](#fieldvalue) requires [`AppliedLabel`](#appliedlabel) ID and resourceDetails ID to be present. *Sample Query*: ``` resourceDetails.id = "resourceId" AND resourceDetails.appliedLabels.id = "appliedLabelId" AND resourceDetails.appliedLabels.fieldValue.id = "fieldValueId" ``` * Filtering on inner [`FieldValue`](#fieldvalue) types like `longTextValue` and `textValue` requires `resourceDetails.appliedLabels.fieldValue.type` to be present. * Only Filtering on a single [`AppliedLabel`](#appliedlabel) id and [`FieldValue`](#fieldvalue) id is supported.',
            },
            maxResults: {
              description:
                "Determines how many activity records are shown on each response page. For example, if the request sets `maxResults=1` and the report has two activities, the report has two pages. The response's `nextPageToken` property has the token to the second page. The `maxResults` query string is optional in the request. The default value is 1000.",
              type: "integer",
              format: "int32",
              default: "1000",
              minimum: "1",
              location: "query",
              maximum: "1000",
            },
            eventName: {
              location: "query",
              type: "string",
              description:
                "The name of the event being queried by the API. Each `eventName` is related to a specific Google Workspace service or feature which the API organizes into types of events. An example is the Google Calendar events in the Admin console application's reports. The Calendar Settings `type` structure has all of the Calendar `eventName` activities reported by the API. When an administrator changes a Calendar setting, the API reports this activity in the Calendar Settings `type` and `eventName` parameters. For more information about `eventName` query strings and parameters, see the list of event names for various applications above in `applicationName`.",
            },
            startTime: {
              type: "string",
              pattern:
                "(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.(\\d+))?(?:(Z)|([-+])(\\d\\d):(\\d\\d))",
              location: "query",
              description:
                "Sets the beginning of the range of time shown in the report. The date is in the RFC 3339 format, for example 2010-10-28T10:26:35.000Z. The report returns all activities from `startTime` until `endTime`. The `startTime` must be before the `endTime` (if specified) and the current time when the request is made, or the API returns an error. For Gmail requests, `startTime` and `endTime` must be provided and the difference must not be greater than 30 days.",
            },
            applicationName: {
              description: "Application name for which the events are to be retrieved.",
              type: "string",
              enum: [
                "access_transparency",
                "admin",
                "calendar",
                "chat",
                "drive",
                "gcp",
                "gmail",
                "gplus",
                "groups",
                "groups_enterprise",
                "jamboard",
                "login",
                "meet",
                "mobile",
                "rules",
                "saml",
                "token",
                "user_accounts",
                "context_aware_access",
                "chrome",
                "data_studio",
                "keep",
                "vault",
                "gemini_in_workspace_apps",
                "classroom",
                "assignments",
                "cloud_search",
                "tasks",
                "data_migration",
                "meet_hardware",
                "directory_sync",
                "ldap",
                "profile",
                "access_evaluation",
                "admin_data_action",
                "contacts",
                "takeout",
                "graduation",
                "voice",
                "chrome_sync",
                "workspace_studio",
                "gemini_notebook",
              ],
              location: "path",
              pattern:
                "(access_evaluation)|(access_transparency)|(admin)|(admin_data_action)|(assignments)|(calendar)|(chat)|(chrome)|(classroom)|(cloud_search)|(contacts)|(context_aware_access)|(data_studio)|(data_migration)|(directory_sync)|(drive)|(gcp)|(gmail)|(gplus)|(graduation)|(groups)|(groups_enterprise)|(jamboard)|(keep)|(ldap)|(login)|(meet)|(meet_hardware)|(mobile)|(profile)|(rules)|(saml)|(token)|(user_accounts)|(vault)|(gemini_in_workspace_apps)|(tasks)|(takeout)|(voice)|(chrome_sync)|(workspace_studio)|(gemini_notebook)",
              required: true,
              enumDescriptions: [
                "The Google Workspace Access Transparency activity reports return information about different types of Access Transparency activity events.",
                "The Admin console application's activity reports return account information about different types of administrator activity events.",
                "The Google Calendar application's activity reports return information about various Calendar activity events.",
                "The Chat activity reports return information about various Chat activity events.",
                "The Google Drive application's activity reports return information about various Google Drive activity events. The Drive activity report is only available for Google Workspace Business and Enterprise customers.",
                "The Google Cloud Platform application's activity reports return information about various GCP activity events.",
                "The Gmail application's activity reports return information about various [Gmail activity events](/admin-sdk/reports/v1/appendix/activity/gmail).",
                "The Google+ application's activity reports return information about various Google+ activity events.",
                "The Google Groups application's activity reports return information about various Groups activity events.",
                "The Enterprise Groups activity reports return information about various Enterprise group activity events.",
                "The Jamboard activity reports return information about various Jamboard activity events.",
                "The Login application's activity reports return account information about different types of Login activity events.",
                "The Meet Audit activity report returns information about different types of Meet Audit activity events.",
                "The Device Audit activity report returns information about different types of Device Audit activity events.",
                "The Rules activity report returns information about different types of Rules activity events.",
                "The SAML activity report returns information about different types of SAML activity events.",
                "The Token application's activity reports return account information about different types of Token activity events.",
                "The User Accounts application's activity reports return account information about different types of User Accounts activity events.",
                "The Context-aware access activity reports return information about users' access denied events due to Context-aware access rules.",
                "The Chrome activity reports return information about Chrome browser and Chrome OS events.",
                "The Data Studio activity reports return information about various types of Data Studio activity events.",
                "The Keep application's activity reports return information about various Google Keep activity events. The Keep activity report is only available for Google Workspace Business and Enterprise customers.",
                "The Vault activity reports return information about various types of Vault activity events.",
                "The Gemini for Workspace activity reports return information about various types of Gemini activity events performed by users within a Workspace application.",
                "The Classroom activity reports return information about different types of [Classroom activity events](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/classroom).",
                "The assignments application's activity reports return information about various types of assignments activity events.",
                "The Cloud Search application's activity reports return information about various types of cloud_search activity events.",
                "The Tasks application's activity reports return information about various types of Tasks activity events.",
                "The Data Migration application's activity reports return information about various types of data migration activity events.",
                "The Meet Hardware application's activity reports return information about various types of Meet Hardware activity events.",
                "The Directory Sync application's activity reports return information about various types of Directory Sync activity events.",
                "The ldap application's activity reports return information about various types of ldap activity events.",
                "The Profile application's activity reports return information about various types of Profile activity events.",
                "The Access Evaluation activity reports return information about various types of Access Evaluation activity events.",
                "The Admin Data Action application's activity reports return information about various types of Admin Data Action activity events.",
                "The Contacts application's activity reports return information about various types of Contacts activity events.",
                "The Takeout application's activity reports return information about various types of Takeout activity events.",
                "The Graduation application's activity reports return information about various types of Graduation activity events.",
                "The Voice application's activity reports return information about various types of Voice activity events.",
                "The Chrome Sync application's activity reports return information about various types of Chrome Sync activity events.",
                "The Workspace Studio application's activity reports return information about various types of Workspace Studio activity events.",
                "The Gemini Notebook application's activity reports return information about various types of Gemini Notebook activity events.",
              ],
            },
          },
        },
        watch: {
          path: "admin/reports/v1/activity/users/{userKey}/applications/{applicationName}/watch",
          response: { $ref: "Channel" },
          description:
            "Start receiving notifications for account activities. For more information, see Receiving Push Notifications.",
          scopes: ["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
          parameters: {
            maxResults: {
              type: "integer",
              description:
                "Determines how many activity records are shown on each response page. For example, if the request sets `maxResults=1` and the report has two activities, the report has two pages. The response's `nextPageToken` property has the token to the second page. The `maxResults` query string is optional in the request. The default value is 1000.",
              format: "int32",
              location: "query",
              minimum: "1",
              default: "1000",
              maximum: "1000",
            },
            endTime: {
              location: "query",
              description:
                "Sets the end of the range of time shown in the report. The date is in the RFC 3339 format, for example 2010-10-28T10:26:35.000Z. The default value is the approximate time of the API request. An API report has three basic time concepts: - *Date of the API's request for a report*: When the API created and retrieved the report. - *Report's start time*: The beginning of the timespan shown in the report. The `startTime` must be before the `endTime` (if specified) and the current time when the request is made, or the API returns an error. - *Report's end time*: The end of the timespan shown in the report. For example, the timespan of events summarized in a report can start in April and end in May. The report itself can be requested in August. If the `endTime` is not specified, the report returns all activities from the `startTime` until the current time or the most recent 180 days if the `startTime` is more than 180 days in the past.",
              pattern:
                "(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.(\\d+))?(?:(Z)|([-+])(\\d\\d):(\\d\\d))",
              type: "string",
            },
            userKey: {
              required: true,
              location: "path",
              description:
                "Represents the profile ID or the user email for which the data should be filtered. Can be `all` for all information, or `userKey` for a user's unique Google Workspace profile ID or their primary email address. Must not be a deleted user. For a deleted user, call `users.list` in Directory API with `showDeleted=true`, then use the returned `ID` as the `userKey`.",
              type: "string",
            },
            filters: {
              pattern: "(.+[<,<=,==,>=,>,<>].+,)*(.+[<,<=,==,>=,>,<>].+)",
              description:
                "The `filters` query string is a comma-separated list composed of event parameters manipulated by relational operators. Event parameters are in the form `{parameter1 name}{relational operator}{parameter1 value},{parameter2 name}{relational operator}{parameter2 value},...` These event parameters are associated with a specific `eventName`. An empty report is returned if the request's parameter doesn't belong to the `eventName`. For more information about the available `eventName` fields for each application and their associated parameters, go to the [ApplicationName](#applicationname) table, then click through to the Activity Events page in the Appendix for the application you want. In the following Drive activity examples, the returned list consists of all `edit` events where the `doc_id` parameter value matches the conditions defined by the relational operator. In the first example, the request returns all edited documents with a `doc_id` value equal to `12345`. In the second example, the report returns any edited documents where the `doc_id` value is not equal to `98765`. The `<>` operator is URL-encoded in the request's query string (`%3C%3E`): ``` GET...&eventName=edit&filters=doc_id==12345 GET...&eventName=edit&filters=doc_id%3C%3E98765 ``` A `filters` query supports these relational operators: * `==`\u2014'equal to'. * `<>`\u2014'not equal to'. Must be URL-encoded (%3C%3E). * `<`\u2014'less than'. Must be URL-encoded (%3C). * `<=`\u2014'less than or equal to'. Must be URL-encoded (%3C=). * `>`\u2014'greater than'. Must be URL-encoded (%3E). * `>=`\u2014'greater than or equal to'. Must be URL-encoded (%3E=). **Note:** The API doesn't accept multiple values of the same parameter. If a parameter is supplied more than once in the API request, the API only accepts the last value of that parameter. In addition, if an invalid parameter is supplied in the API request, the API ignores that parameter and returns the response corresponding to the remaining valid parameters. If no parameters are requested, all parameters are returned.",
              location: "query",
              type: "string",
            },
            applicationName: {
              enum: [
                "access_transparency",
                "admin",
                "calendar",
                "chat",
                "drive",
                "gcp",
                "gplus",
                "groups",
                "groups_enterprise",
                "jamboard",
                "login",
                "meet",
                "mobile",
                "rules",
                "saml",
                "token",
                "user_accounts",
                "context_aware_access",
                "chrome",
                "data_studio",
                "keep",
                "classroom",
              ],
              required: true,
              location: "path",
              enumDescriptions: [
                "The Google Workspace Access Transparency activity reports return information about different types of Access Transparency activity events.",
                "The Admin console application's activity reports return account information about different types of administrator activity events.",
                "The Google Calendar application's activity reports return information about various Calendar activity events.",
                "The Chat activity reports return information about various Chat activity events.",
                "The Google Drive application's activity reports return information about various Google Drive activity events. The Drive activity report is only available for Google Workspace Business and Google Workspace Enterprise customers.",
                "The Google Cloud Platform application's activity reports return information about various GCP activity events.",
                "The Google+ application's activity reports return information about various Google+ activity events.",
                "The Google Groups application's activity reports return information about various Groups activity events.",
                "The Enterprise Groups activity reports return information about various Enterprise group activity events.",
                "The Jamboard activity reports return information about various Jamboard activity events.",
                "The Login application's activity reports return account information about different types of Login activity events.",
                "The Meet Audit activity report returns information about different types of Meet Audit activity events.",
                "The Device Audit activity report returns information about different types of Device Audit activity events.",
                "The Rules activity report returns information about different types of Rules activity events.",
                "The SAML activity report returns information about different types of SAML activity events.",
                "The Token application's activity reports return account information about different types of Token activity events.",
                "The User Accounts application's activity reports return account information about different types of User Accounts activity events.",
                "The Context-aware access activity reports return information about users' access denied events due to Context-aware access rules.",
                "The Chrome activity reports return information about Chrome browser and Chrome OS events.",
                "The Data Studio activity reports return information about various types of Data Studio activity events.",
                "The Keep application's activity reports return information about various Google Keep activity events. The Keep activity report is only available for Google Workspace Business and Enterprise customers.",
                "The Classroom activity reports return information about different types of [Classroom activity events](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/classroom).",
              ],
              description: "Application name for which the events are to be retrieved.",
              type: "string",
              pattern:
                "(access_transparency)|(admin)|(calendar)|(chat)|(chrome)|(classroom)|(context_aware_access)|(data_studio)|(drive)|(gcp)|(gplus)|(groups)|(groups_enterprise)|(jamboard)|(keep)|(login)|(meet)|(mobile)|(rules)|(saml)|(token)|(user_accounts)",
            },
            groupIdFilter: {
              location: "query",
              description:
                '`Deprecated`. This field is deprecated and is no longer supported. Comma separated group ids (obfuscated) on which user activities are filtered, i.e. the response will contain activities for only those users that are a part of at least one of the group ids mentioned here. Format: "id:abc123,id:xyz456" *Important:* To filter by groups, you must explicitly add the groups to your filtering groups allowlist. For more information about adding groups to filtering groups allowlist, see [Filter results by Google Group](https://support.google.com/a/answer/11482175)',
              type: "string",
              pattern: "(id:[a-z0-9]+(,id:[a-z0-9]+)*)",
              deprecated: true,
            },
            orgUnitID: {
              location: "query",
              deprecated: true,
              description:
                "`Deprecated`. This field is deprecated and is no longer supported. ID of the organizational unit to report on. Activity records will be shown only for users who belong to the specified organizational unit. Data before Dec 17, 2018 doesn't appear in the filtered results.",
              default: "",
              pattern: "(id:[a-z0-9]+)",
              type: "string",
            },
            pageToken: {
              location: "query",
              description:
                "The token to specify next page. A report with multiple pages has a `nextPageToken` property in the response. In your follow-on request getting the next page of the report, enter the `nextPageToken` value in the `pageToken` query string.",
              type: "string",
            },
            startTime: {
              description:
                "Sets the beginning of the range of time shown in the report. The date is in the RFC 3339 format, for example 2010-10-28T10:26:35.000Z. The report returns all activities from `startTime` until `endTime`. The `startTime` must be before the `endTime` (if specified) and the current time when the request is made, or the API returns an error.",
              pattern:
                "(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.(\\d+))?(?:(Z)|([-+])(\\d\\d):(\\d\\d))",
              type: "string",
              location: "query",
            },
            customerId: {
              description: "The unique ID of the customer to retrieve data for.",
              type: "string",
              pattern: "C.+|my_customer",
              location: "query",
            },
            eventName: {
              location: "query",
              description:
                "The name of the event being queried by the API. Each `eventName` is related to a specific Google Workspace service or feature which the API organizes into types of events. An example is the Google Calendar events in the Admin console application's reports. The Calendar Settings `type` structure has all of the Calendar `eventName` activities reported by the API. When an administrator changes a Calendar setting, the API reports this activity in the Calendar Settings `type` and `eventName` parameters. For more information about `eventName` query strings and parameters, see the list of event names for various applications above in `applicationName`.",
              type: "string",
            },
            actorIpAddress: {
              type: "string",
              location: "query",
              description:
                "The Internet Protocol (IP) Address of host where the event was performed. This is an additional way to filter a report's summary using the IP address of the user whose activity is being reported. This IP address may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. This parameter supports both IPv4 and IPv6 address versions.",
            },
          },
          parameterOrder: ["userKey", "applicationName"],
          request: { $ref: "Channel" },
          httpMethod: "POST",
          id: "reports.activities.watch",
          flatPath: "admin/reports/v1/activity/users/{userKey}/applications/{applicationName}/watch",
        },
      },
    },
    channels: {
      methods: {
        stop: {
          path: "admin/reports_v1/channels/stop",
          scopes: ["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
          parameterOrder: [],
          httpMethod: "POST",
          flatPath: "admin/reports_v1/channels/stop",
          description: "Stop watching resources through this channel.",
          id: "admin.channels.stop",
          request: { $ref: "Channel" },
          parameters: {},
        },
      },
    },
  },
} as const;

/** The OAuth scopes each Reports route accepts, keyed as `METHOD /path/:param`, from the methods above. */
export const reportsRouteScopes: Record<string, readonly string[]> = Object.fromEntries(
  Object.values(document.resources).flatMap((resource) =>
    Object.values(resource.methods).map((method) => [
      `${method.httpMethod} /${method.flatPath.replace(/\{(\w+)\}/g, ":$1")}`,
      method.scopes,
    ]),
  ),
);

export function buildReportsDiscoveryDocument(baseUrl: string) {
  const rootUrl = `${baseUrl.replace(/\/$/, "")}/`;
  return { ...document, rootUrl, baseUrl: rootUrl, servicePath: "", basePath: "", batchPath: "batch" };
}
