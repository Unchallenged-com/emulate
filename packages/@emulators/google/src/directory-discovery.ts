// A subset of Google's Admin SDK Directory API discovery document (revision 20261109): the methods,
// parameters and resource fields this emulator implements, as Google publishes them.
const document = {
  kind: "discovery#restDescription",
  discoveryVersion: "v1",
  id: "admin:directory_v1",
  name: "admin",
  canonicalName: "directory",
  version: "directory_v1",
  revision: "20261109",
  title: "Admin SDK API",
  description:
    "Admin SDK lets administrators of enterprise domains to view and manage resources like user, groups etc. It also provides audit and usage reports of domain.",
  ownerDomain: "google.com",
  ownerName: "Google",
  documentationLink: "https://developers.google.com/workspace/admin/",
  protocol: "rest",
  parameters: {
    uploadType: {
      location: "query",
      description: 'Legacy upload protocol for media (e.g. "media", "multipart").',
      type: "string",
    },
    access_token: {
      description: "OAuth access token.",
      location: "query",
      type: "string",
    },
    alt: {
      location: "query",
      enum: ["json", "media", "proto"],
      type: "string",
      enumDescriptions: [
        "Responses with Content-Type of application/json",
        "Media download with context-dependent Content-Type",
        "Responses with Content-Type of application/x-protobuf",
      ],
      description: "Data format for response.",
      default: "json",
    },
    quotaUser: {
      type: "string",
      description:
        "Available to use for quota purposes for server-side applications. Can be any arbitrary string assigned to a user, but should not exceed 40 characters.",
      location: "query",
    },
    "$.xgafv": {
      enum: ["1", "2"],
      enumDescriptions: ["v1 error format", "v2 error format"],
      location: "query",
      type: "string",
      description: "V1 error format.",
    },
    upload_protocol: {
      description: 'Upload protocol for media (e.g. "raw", "multipart").',
      type: "string",
      location: "query",
    },
    key: {
      location: "query",
      description:
        "API key. Your API key identifies your project and provides you with API access, quota, and reports. Required unless you provide an OAuth 2.0 token.",
      type: "string",
    },
    oauth_token: {
      location: "query",
      type: "string",
      description: "OAuth 2.0 token for the current user.",
    },
    prettyPrint: {
      default: "true",
      description: "Returns response with indentations and line breaks.",
      location: "query",
      type: "boolean",
    },
    callback: {
      description: "JSONP",
      location: "query",
      type: "string",
    },
    fields: {
      description: "Selector specifying which fields to include in a partial response.",
      type: "string",
      location: "query",
    },
  },
  auth: {
    oauth2: {
      scopes: {
        "https://www.googleapis.com/auth/admin.directory.group": {
          description: "View and manage the provisioning of groups on your domain",
        },
        "https://www.googleapis.com/auth/admin.directory.group.member": {
          description: "View and manage group subscriptions on your domain",
        },
        "https://www.googleapis.com/auth/admin.directory.group.member.readonly": {
          description: "View group subscriptions on your domain",
        },
        "https://www.googleapis.com/auth/admin.directory.group.readonly": {
          description: "View groups on your domain",
        },
        "https://www.googleapis.com/auth/admin.directory.user": {
          description: "View and manage the provisioning of users on your domain",
        },
        "https://www.googleapis.com/auth/admin.directory.user.readonly": {
          description: "See info about users on your domain",
        },
        "https://www.googleapis.com/auth/cloud-platform": {
          description:
            "See, edit, configure, and delete your Google Cloud data and see the email address for your Google Account.",
        },
      },
    },
  },
  schemas: {
    User: {
      id: "User",
      properties: {
        kind: {
          description:
            "Output only. The type of the API resource. For Users resources, the value is `admin#directory#user`.",
          readOnly: true,
          type: "string",
          default: "admin#directory#user",
        },
        id: {
          description: "The unique ID for the user. A user `id` can be used as a user request URI's `userKey`.",
          type: "string",
        },
        etag: {
          readOnly: true,
          description: "Output only. ETag of the resource.",
          type: "string",
        },
        primaryEmail: {
          type: "string",
          description:
            "The user's primary email address. This property is required in a request to create a user account. The `primaryEmail` must be unique and cannot be an alias of another user.",
          annotations: {
            required: ["directory.users.insert"],
          },
        },
        password: {
          type: "string",
          description: "User's password",
          annotations: {
            required: ["directory.users.insert"],
          },
        },
        hashFunction: {
          type: "string",
          description:
            "Stores the hash format of the `password` property. The following `hashFunction` values are allowed: * `MD5` - Accepts simple hex-encoded values. * `SHA-1` - Accepts simple hex-encoded values. * `crypt` - Compliant with the [C crypt library](https://en.wikipedia.org/wiki/Crypt_%28C%29). Supports the DES, MD5 (hash prefix `$1$`), SHA-256 (hash prefix `$5$`), and SHA-512 (hash prefix `$6$`) hash algorithms. If rounds are specified as part of the prefix, they must be 10,000 or fewer.",
        },
        name: {
          description:
            "Holds the given and family names of the user, and the read-only `fullName` value. The maximum number of characters in the `givenName` and in the `familyName` values is 60. In addition, name values support unicode/UTF-8 characters, and can contain spaces, letters (a-z), numbers (0-9), dashes (-), forward slashes (/), and periods (.). For more information about character usage rules, see the [administration help center](https://support.google.com/a/answer/9193374). Maximum allowed data size for this field is 1KB.",
          annotations: {
            required: ["directory.users.insert"],
          },
          $ref: "UserName",
        },
        isAdmin: {
          description:
            "Output only. Indicates a user with super administrator privileges. The `isAdmin` property can only be edited in the [Make a user an administrator](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users.html#make_admin) operation ( [makeAdmin](https://developers.google.com/workspace/admin/directory/v1/reference/users/makeAdmin.html) method). If edited in the user [insert](https://developers.google.com/workspace/admin/directory/v1/reference/users/insert.html) or [update](https://developers.google.com/workspace/admin/directory/v1/reference/users/update.html) methods, the edit is ignored by the API service.",
          type: "boolean",
          readOnly: true,
        },
        isDelegatedAdmin: {
          description:
            "Output only. Indicates if the user is a delegated administrator. Delegated administrators are supported by the API but cannot create or undelete users, or make users administrators. These requests are ignored by the API service. Roles and privileges for administrators are assigned using the [Admin console](https://support.google.com/a/answer/33325).",
          readOnly: true,
          type: "boolean",
        },
        lastLoginTime: {
          format: "date-time",
          type: "string",
          description: "User's last login time. (Read-only)",
          readOnly: true,
        },
        creationTime: {
          type: "string",
          description: "User's G Suite account creation time. (Read-only)",
          format: "date-time",
          readOnly: true,
        },
        agreedToTerms: {
          description:
            "Output only. This property is `true` if the user has completed an initial login and accepted the Terms of Service agreement.",
          readOnly: true,
          type: "boolean",
        },
        suspended: {
          description: "Indicates if user is suspended.",
          type: "boolean",
        },
        suspensionReason: {
          description:
            "Output only. Has the reason a user account is suspended either by the administrator or by Google at the time of suspension. The property is returned only if the `suspended` property is `true`.",
          type: "string",
          readOnly: true,
        },
        archived: {
          description: "Indicates if user is archived.",
          type: "boolean",
        },
        changePasswordAtNextLogin: {
          type: "boolean",
          description:
            "Indicates if the user is forced to change their password at next login. This setting doesn't apply when [the user signs in via a third-party identity provider](https://support.google.com/a/answer/60224).",
        },
        ipWhitelisted: {
          description:
            "If `true`, the user's IP address is subject to a deprecated IP address [`allowlist`](https://support.google.com/a/answer/60752) configuration.",
          type: "boolean",
        },
        emails: {
          type: "any",
          description:
            "The list of the user's email addresses. The maximum allowed data size for this field is 10KB. This excludes `publicKeyEncryptionCertificates`.",
        },
        customerId: {
          description:
            "Output only. The customer ID to [retrieve all account users](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users.html#get_all_users). You can use the alias `my_customer` to represent your account's `customerId`. As a reseller administrator, you can use the resold customer account's `customerId`. To get a `customerId`, use the account's primary domain in the `domain` parameter of a [users.list](https://developers.google.com/workspace/admin/directory/v1/reference/users/list) request.",
          type: "string",
          readOnly: true,
        },
        orgUnitPath: {
          description:
            "The full path of the parent organization associated with the user. If the parent organization is the top-level, it is represented as a forward slash (`/`).",
          type: "string",
        },
        includeInGlobalAddressList: {
          type: "boolean",
          description:
            "Indicates if the user's profile is visible in the Google Workspace global address list when the contact sharing feature is enabled for the domain. For more information about excluding user profiles, see the [administration help center](https://support.google.com/a/answer/1285988).",
        },
        isEnrolledIn2Sv: {
          type: "boolean",
          readOnly: true,
          description: "Output only. Is enrolled in 2-step verification (Read-only)",
        },
        isEnforcedIn2Sv: {
          readOnly: true,
          description: "Output only. Is 2-step verification enforced (Read-only)",
          type: "boolean",
        },
      },
      description:
        "The Directory API allows you to create and manage your account's users, user aliases, and user Google profile photos. For more information about common tasks, see the [User Accounts Developer's Guide](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users.html) and the [User Aliases Developer's Guide](https://developers.google.com/workspace/admin/directory/v1/guides/manage-user-aliases.html).",
      type: "object",
    },
    UserName: {
      id: "UserName",
      type: "object",
      properties: {
        givenName: {
          type: "string",
          description: "The user's first name. Required when creating a user account.",
          annotations: {
            required: ["directory.users.insert"],
          },
        },
        familyName: {
          description: "The user's last name. Required when creating a user account.",
          annotations: {
            required: ["directory.users.insert"],
          },
          type: "string",
        },
        fullName: {
          description: "The user's full name formed by concatenating the first and last name values.",
          type: "string",
        },
        displayName: {
          type: "string",
          description: "The user's display name. Limit: 256 characters.",
        },
      },
    },
    Users: {
      id: "Users",
      type: "object",
      properties: {
        kind: {
          type: "string",
          description: "Kind of resource this is.",
          default: "admin#directory#users",
        },
        etag: {
          description: "ETag of the resource.",
          type: "string",
        },
        users: {
          description: "A list of user objects.",
          type: "array",
          items: {
            $ref: "User",
          },
        },
        nextPageToken: {
          type: "string",
          description: "Token used to access next page of this result. The page token is only valid for three days.",
        },
      },
    },
    Group: {
      description:
        "Google Groups provide your users the ability to send messages to groups of people using the group's email address. For more information about common tasks, see the [Developer's Guide](https://developers.google.com/workspace/admin/directory/v1/guides/manage-groups). For information about other types of groups, see the [Cloud Identity Groups API documentation](https://cloud.google.com/identity/docs/groups). Note: The user calling the API (or being impersonated by a service account) must have an assigned [role](https://developers.google.com/workspace/admin/directory/v1/guides/manage-roles) that includes Admin API Groups permissions, such as Super Admin or Groups Admin.",
      properties: {
        kind: {
          description: "The type of the API resource. For Groups resources, the value is `admin#directory#group`.",
          type: "string",
          default: "admin#directory#group",
        },
        id: {
          description:
            "Read-only. The unique ID of a group. A group `id` can be used as a group request URI's `groupKey`.",
          type: "string",
        },
        etag: {
          description: "ETag of the resource.",
          type: "string",
        },
        email: {
          type: "string",
          description:
            "The group's email address. If your account has multiple domains, select the appropriate domain for the email address. The `email` must be unique. This property is required when creating a group. Group email addresses are subject to the same character usage rules as usernames, see the [help center](https://support.google.com/a/answer/9193374) for details.",
          annotations: {
            required: ["directory.groups.insert"],
          },
        },
        name: {
          type: "string",
          description: "The group's display name.",
        },
        description: {
          description:
            "An extended description to help users determine the purpose of a group. For example, you can include information about who should join the group, the types of messages to send to the group, links to FAQs about the group, or related groups. Maximum length is `4,096` characters.",
          type: "string",
        },
        directMembersCount: {
          description:
            "The number of users that are direct members of the group. If a group is a member (child) of this group (the parent), members of the child group are not counted in the `directMembersCount` property of the parent group.",
          format: "int64",
          type: "string",
        },
        adminCreated: {
          description: "Read-only. Value is `true` if this group was created by an administrator rather than a user.",
          type: "boolean",
        },
        aliases: {
          type: "array",
          description:
            "Read-only. The list of a group's alias email addresses. To add, update, or remove a group's aliases, use the `groups.aliases` methods. If edited in a group's POST or PUT request, the edit is ignored.",
          items: {
            type: "string",
          },
        },
        nonEditableAliases: {
          description:
            "Read-only. The list of the group's non-editable alias email addresses that are outside of the account's primary domain or subdomains. These are functioning email addresses used by the group. This is a read-only property returned in the API's response for a group. If edited in a group's POST or PUT request, the edit is ignored.",
          items: {
            type: "string",
          },
          type: "array",
        },
      },
      type: "object",
      id: "Group",
    },
    Groups: {
      id: "Groups",
      type: "object",
      properties: {
        kind: {
          description: "Kind of resource this is.",
          default: "admin#directory#groups",
          type: "string",
        },
        etag: {
          type: "string",
          description: "ETag of the resource.",
        },
        groups: {
          type: "array",
          items: {
            $ref: "Group",
          },
          description: "A list of group objects.",
        },
        nextPageToken: {
          type: "string",
          description: "Token used to access next page of this result.",
        },
      },
    },
    Member: {
      description:
        "A Google Groups member can be a user or another group. This member can be inside or outside of your account's domains. For more information about common group member tasks, see the [Developer's Guide](https://developers.google.com/workspace/admin/directory/v1/guides/manage-group-members).",
      id: "Member",
      type: "object",
      properties: {
        kind: {
          default: "admin#directory#member",
          description: "The type of the API resource. For Members resources, the value is `admin#directory#member`.",
          type: "string",
        },
        etag: {
          type: "string",
          description: "ETag of the resource.",
        },
        id: {
          description:
            "The unique ID of the group member. A member `id` can be used as a member request URI's `memberKey`.",
          type: "string",
        },
        email: {
          type: "string",
          description:
            "The member's email address. A member can be a user or another group. This property is required when adding a member to a group. The `email` must be unique and cannot be an alias of another group. If the email address is changed, the API automatically reflects the email address changes.",
        },
        role: {
          description:
            "The member's role in a group. The API returns an error for cycles in group memberships. For example, if `group1` is a member of `group2`, `group2` cannot be a member of `group1`. For more information about a member's role, see the [administration help center](https://support.google.com/a/answer/167094).",
          type: "string",
        },
        type: {
          description: "The type of group member.",
          type: "string",
        },
        status: {
          description: "Status of member (Immutable)",
          type: "string",
        },
        delivery_settings: {
          description:
            "Defines mail delivery preferences of member. This field is only supported by `insert`, `update`, and `get` methods.",
          type: "string",
        },
      },
    },
    Members: {
      properties: {
        kind: {
          description: "Kind of resource this is.",
          default: "admin#directory#members",
          type: "string",
        },
        etag: {
          description: "ETag of the resource.",
          type: "string",
        },
        members: {
          type: "array",
          items: {
            $ref: "Member",
          },
          description: "A list of member objects.",
        },
        nextPageToken: {
          description: "Token used to access next page of this result.",
          type: "string",
        },
      },
      type: "object",
      id: "Members",
    },
    MembersHasMember: {
      description: "JSON template for Has Member response in Directory API.",
      properties: {
        isMember: {
          type: "boolean",
          description:
            "Output only. Identifies whether the given user is a member of the group. Membership can be direct or nested.",
          readOnly: true,
        },
      },
      type: "object",
      id: "MembersHasMember",
    },
  },
  resources: {
    users: {
      methods: {
        list: {
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/cloud-platform",
          ],
          httpMethod: "GET",
          response: {
            $ref: "Users",
          },
          parameters: {
            pageToken: {
              location: "query",
              type: "string",
              description: "Token to specify next page in the list. The page token is only valid for three days.",
            },
            projection: {
              location: "query",
              enum: ["basic", "custom", "full"],
              enumDescriptions: [
                "Do not include any custom fields for the user.",
                "Include custom fields from schemas requested in `customFieldMask`.",
                "Include all fields associated with this user.",
              ],
              default: "basic",
              type: "string",
              description: "What subset of fields to fetch for this user.",
            },
            viewType: {
              location: "query",
              description:
                "Whether to fetch the administrator-only or domain-wide public view of the user. For more information, see [Retrieve a user as a non-administrator](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users#retrieve_users_non_admin).",
              type: "string",
              enumDescriptions: [
                "Results include both administrator-only and domain-public fields for the user.",
                "Results only include fields for the user that are publicly visible to other users in the domain.",
              ],
              default: "admin_view",
              enum: ["admin_view", "domain_public"],
            },
            sortOrder: {
              enumDescriptions: ["Ascending order.", "Descending order."],
              type: "string",
              description: "Whether to return results in ascending or descending order, ignoring case.",
              location: "query",
              enum: ["ASCENDING", "DESCENDING"],
            },
            domain: {
              location: "query",
              description:
                "The domain name. Use this field to get users from only one domain. To return all domains for a customer account, use the `customer` query parameter instead. Either the `customer` or the `domain` parameter must be provided.",
              type: "string",
            },
            customer: {
              location: "query",
              description:
                "The unique ID for the customer's Google Workspace account. In case of a multi-domain account, to fetch all users for a customer, use this field instead of `domain`. You can also use the `my_customer` alias to represent your account's `customerId`. The `customerId` is also returned as part of the [Users](https://developers.google.com/workspace/admin/directory/v1/reference/users) resource. You must provide either the `customer` or the `domain` parameter.",
              type: "string",
            },
            orderBy: {
              enumDescriptions: ["Primary email of the user.", "User's family name.", "User's given name."],
              location: "query",
              enum: ["email", "familyName", "givenName"],
              description: "Property to use for sorting results.",
              type: "string",
            },
            maxResults: {
              maximum: "500",
              description: "Maximum number of results to return.",
              format: "int32",
              location: "query",
              type: "integer",
              minimum: "1",
              default: "100",
            },
          },
          path: "admin/directory/v1/users",
          description: "Retrieves a paginated list of either deleted users or all users in a domain.",
          id: "directory.users.list",
          flatPath: "admin/directory/v1/users",
          parameterOrder: [],
        },
        get: {
          response: {
            $ref: "User",
          },
          id: "directory.users.get",
          parameters: {
            viewType: {
              enumDescriptions: [
                "Results include both administrator-only and domain-public fields for the user.",
                "Results only include fields for the user that are publicly visible to other users in the domain.",
              ],
              type: "string",
              location: "query",
              enum: ["admin_view", "domain_public"],
              description:
                "Whether to fetch the administrator-only or domain-wide public view of the user. For more information, see [Retrieve a user as a non-administrator](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users#retrieve_users_non_admin).",
              default: "admin_view",
            },
            userKey: {
              required: true,
              description:
                "Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID.",
              type: "string",
              location: "path",
            },
            projection: {
              default: "basic",
              description: "What subset of fields to fetch for this user.",
              enum: ["basic", "custom", "full"],
              enumDescriptions: [
                "Do not include any custom fields for the user.",
                "Include custom fields from schemas requested in `customFieldMask`.",
                "Include all fields associated with this user.",
              ],
              type: "string",
              location: "query",
            },
          },
          httpMethod: "GET",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
          ],
          path: "admin/directory/v1/users/{userKey}",
          parameterOrder: ["userKey"],
          flatPath: "admin/directory/v1/users/{userKey}",
          description: "Retrieves a user.",
        },
        insert: {
          response: {
            $ref: "User",
          },
          scopes: ["https://www.googleapis.com/auth/admin.directory.user"],
          parameterOrder: [],
          description:
            "Creates a user. Mutate calls immediately following user creation might sometimes fail as the user isn't fully created due to propagation delay in our backends. Check the error details for the \"User creation is not complete\" message to see if this is the case. Retrying the calls after some time can help in this case. If `resolve_conflict_account` is set to `true`, the option selected for [Find and add unmanaged users](https://knowledge.workspace.google.com/admin/users/find-and-add-unmanaged-users) will apply to resolve conflicting accounts: - A `200` response code indicates the user was created (or replaced an existing unmanaged personal account). - A `202` response code means that a conflicting unmanaged personal account exists and was invited to join the organization. - A `409` response code means that a conflicting account exists so the user wasn't created (e.g. based on the option selected to preserve the account, or if the email conflicts with an unmanaged work account or existing managed user). For details on resolving duplicate account errors, see [Resolve duplicate account errors](https://knowledge.workspace.google.com/p/duplicate-account-errors) and [Transfer unmanaged work accounts](https://knowledge.workspace.google.com/p/unmanaged-work-accounts).",
          request: {
            $ref: "User",
          },
          id: "directory.users.insert",
          parameters: {
            resolveConflictAccount: {
              type: "boolean",
              location: "query",
              description:
                "Optional. Applies the option selected for [Find and add unmanaged users](https://knowledge.workspace.google.com/admin/users/find-and-add-unmanaged-users) to resolve conflicting accounts when set to `true`. Default: `false`",
            },
          },
          flatPath: "admin/directory/v1/users",
          httpMethod: "POST",
          path: "admin/directory/v1/users",
        },
        update: {
          parameterOrder: ["userKey"],
          path: "admin/directory/v1/users/{userKey}",
          httpMethod: "PUT",
          request: {
            $ref: "User",
          },
          parameters: {
            userKey: {
              type: "string",
              location: "path",
              description:
                "Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID.",
              required: true,
            },
          },
          response: {
            $ref: "User",
          },
          id: "directory.users.update",
          scopes: ["https://www.googleapis.com/auth/admin.directory.user"],
          flatPath: "admin/directory/v1/users/{userKey}",
          description:
            "Updates a user. This method supports patch semantics, meaning that you only need to include the fields you wish to update. Fields that are not present in the request will be preserved, and fields set to `null` will be cleared. For repeating fields that contain arrays, individual items in the array can't be patched piecemeal; they must be supplied in the request body with the desired values for all items. See the [user accounts guide](https://developers.google.com/workspace/admin/directory/v1/guides/manage-users#update_user) for more information.",
        },
        patch: {
          description:
            "Updates a user using patch semantics. The update method should be used instead, because it also supports patch semantics and has better performance. If you're mapping an external identity to a Google identity, use the [`update`](https://developers.google.com/workspace/admin/directory/v1/reference/users/update) method instead of the `patch` method. This method is unable to clear fields that contain repeated objects (`addresses`, `phones`, etc). Use the update method instead.",
          flatPath: "admin/directory/v1/users/{userKey}",
          id: "directory.users.patch",
          httpMethod: "PATCH",
          parameters: {
            userKey: {
              required: true,
              description:
                "Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID.",
              type: "string",
              location: "path",
            },
          },
          path: "admin/directory/v1/users/{userKey}",
          request: {
            $ref: "User",
          },
          scopes: ["https://www.googleapis.com/auth/admin.directory.user"],
          response: {
            $ref: "User",
          },
          parameterOrder: ["userKey"],
        },
        delete: {
          parameters: {
            userKey: {
              description:
                "Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID.",
              location: "path",
              type: "string",
              required: true,
            },
          },
          scopes: ["https://www.googleapis.com/auth/admin.directory.user"],
          path: "admin/directory/v1/users/{userKey}",
          id: "directory.users.delete",
          description: "Deletes a user.",
          flatPath: "admin/directory/v1/users/{userKey}",
          parameterOrder: ["userKey"],
          httpMethod: "DELETE",
        },
      },
    },
    groups: {
      methods: {
        list: {
          flatPath: "admin/directory/v1/groups",
          id: "directory.groups.list",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
          ],
          description: "Retrieves all groups of a domain or of a user given a userKey (paginated).",
          parameters: {
            domain: {
              location: "query",
              description:
                "The domain name. Use this field to get groups from only one domain. To return all domains for a customer account, use the `customer` query parameter instead.",
              type: "string",
            },
            pageToken: {
              description: "Token to specify next page in the list",
              location: "query",
              type: "string",
            },
            maxResults: {
              minimum: "1",
              description: "Maximum number of results to return. Max allowed value is 200.",
              default: "200",
              format: "int32",
              type: "integer",
              location: "query",
            },
            orderBy: {
              enumDescriptions: ["Email of the group."],
              enum: ["email"],
              location: "query",
              description: "Column to use for sorting results",
              type: "string",
            },
            sortOrder: {
              enum: ["ASCENDING", "DESCENDING"],
              enumDescriptions: ["Ascending order.", "Descending order."],
              description:
                "Whether to return results in ascending or descending order. Only of use when orderBy is also used",
              location: "query",
              type: "string",
            },
            customer: {
              location: "query",
              type: "string",
              description:
                "The unique ID for the customer's Google Workspace account. In case of a multi-domain account, to fetch all groups for a customer, use this field instead of `domain`. You can also use the `my_customer` alias to represent your account's `customerId`. The `customerId` is also returned as part of the [Users](https://developers.google.com/workspace/admin/directory/v1/reference/users) resource. You must provide either the `customer` or the `domain` parameter.",
            },
            userKey: {
              description:
                "Email or immutable ID of the user if only those groups are to be listed, the given user is a member of. If it's an ID, it should match with the ID of the user object. Cannot be used with the `customer` parameter.",
              location: "query",
              type: "string",
            },
          },
          parameterOrder: [],
          path: "admin/directory/v1/groups",
          httpMethod: "GET",
          response: {
            $ref: "Groups",
          },
        },
        get: {
          response: {
            $ref: "Group",
          },
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
          ],
          description: "Retrieves a group's properties.",
          parameterOrder: ["groupKey"],
          id: "directory.groups.get",
          parameters: {
            groupKey: {
              required: true,
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              location: "path",
              type: "string",
            },
          },
          flatPath: "admin/directory/v1/groups/{groupKey}",
          httpMethod: "GET",
          path: "admin/directory/v1/groups/{groupKey}",
        },
        insert: {
          id: "directory.groups.insert",
          flatPath: "admin/directory/v1/groups",
          description: "Creates a group.",
          path: "admin/directory/v1/groups",
          request: {
            $ref: "Group",
          },
          scopes: ["https://www.googleapis.com/auth/admin.directory.group"],
          parameters: {},
          parameterOrder: [],
          response: {
            $ref: "Group",
          },
          httpMethod: "POST",
        },
        update: {
          request: {
            $ref: "Group",
          },
          httpMethod: "PUT",
          description: "Updates a group's properties.",
          parameters: {
            groupKey: {
              required: true,
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              type: "string",
              location: "path",
            },
          },
          response: {
            $ref: "Group",
          },
          path: "admin/directory/v1/groups/{groupKey}",
          parameterOrder: ["groupKey"],
          scopes: ["https://www.googleapis.com/auth/admin.directory.group"],
          flatPath: "admin/directory/v1/groups/{groupKey}",
          id: "directory.groups.update",
        },
        patch: {
          flatPath: "admin/directory/v1/groups/{groupKey}",
          description:
            "Updates a group's properties. This method supports [patch semantics](https://developers.google.com/workspace/admin/directory/v1/guides/performance#patch).",
          path: "admin/directory/v1/groups/{groupKey}",
          parameterOrder: ["groupKey"],
          request: {
            $ref: "Group",
          },
          response: {
            $ref: "Group",
          },
          httpMethod: "PATCH",
          parameters: {
            groupKey: {
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              location: "path",
              type: "string",
              required: true,
            },
          },
          id: "directory.groups.patch",
          scopes: ["https://www.googleapis.com/auth/admin.directory.group"],
        },
        delete: {
          id: "directory.groups.delete",
          parameters: {
            groupKey: {
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              required: true,
              location: "path",
              type: "string",
            },
          },
          path: "admin/directory/v1/groups/{groupKey}",
          description: "Deletes a group.",
          flatPath: "admin/directory/v1/groups/{groupKey}",
          parameterOrder: ["groupKey"],
          httpMethod: "DELETE",
          scopes: ["https://www.googleapis.com/auth/admin.directory.group"],
        },
      },
    },
    members: {
      methods: {
        list: {
          id: "directory.members.list",
          flatPath: "admin/directory/v1/groups/{groupKey}/members",
          path: "admin/directory/v1/groups/{groupKey}/members",
          parameters: {
            includeDerivedMembership: {
              location: "query",
              type: "boolean",
              description: "Whether to list indirect memberships. Default: false.",
            },
            groupKey: {
              location: "path",
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              type: "string",
              required: true,
            },
            maxResults: {
              location: "query",
              description: "Maximum number of results to return. Max allowed value is 200.",
              format: "int32",
              type: "integer",
              minimum: "1",
              default: "200",
            },
            pageToken: {
              type: "string",
              description: "Token to specify next page in the list.",
              location: "query",
            },
            roles: {
              location: "query",
              type: "string",
              description:
                "The `roles` query parameter allows you to retrieve group members by role. Allowed values are `OWNER`, `MANAGER`, and `MEMBER`.",
            },
          },
          parameterOrder: ["groupKey"],
          httpMethod: "GET",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
          ],
          response: {
            $ref: "Members",
          },
          description:
            "Retrieves a paginated list of all members in a group. This method times out after 60 minutes. For more information, see [Troubleshoot error codes](https://developers.google.com/workspace/admin/directory/v1/guides/troubleshoot-error-codes).",
        },
        get: {
          httpMethod: "GET",
          description: "Retrieves a group member's properties.",
          flatPath: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          parameters: {
            memberKey: {
              required: true,
              description:
                "Identifies the group member in the API request. A group member can be a user or another group. The value can be the member's (group or user) primary email address, alias, or unique ID.",
              location: "path",
              type: "string",
            },
            groupKey: {
              type: "string",
              location: "path",
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              required: true,
            },
          },
          path: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
          ],
          id: "directory.members.get",
          response: {
            $ref: "Member",
          },
          parameterOrder: ["groupKey", "memberKey"],
        },
        hasMember: {
          response: {
            $ref: "MembersHasMember",
          },
          description:
            "Checks whether the given user is a member of the group. Membership can be direct or nested, but if nested, the `memberKey` and `groupKey` must be entities in the same domain or an `Invalid input` error is returned. To check for nested memberships that include entities outside of the group's domain, use the [`checkTransitiveMembership()`](https://cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/checkTransitiveMembership) method in the Cloud Identity Groups API.",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
          ],
          flatPath: "admin/directory/v1/groups/{groupKey}/hasMember/{memberKey}",
          parameters: {
            memberKey: {
              description:
                "Identifies the user member in the API request. The value can be the user's primary email address, alias, or unique ID.",
              location: "path",
              required: true,
              type: "string",
            },
            groupKey: {
              type: "string",
              required: true,
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              location: "path",
            },
          },
          httpMethod: "GET",
          id: "directory.members.hasMember",
          path: "admin/directory/v1/groups/{groupKey}/hasMember/{memberKey}",
          parameterOrder: ["groupKey", "memberKey"],
        },
        insert: {
          description: "Adds a user to the specified group.",
          httpMethod: "POST",
          request: {
            $ref: "Member",
          },
          parameters: {
            groupKey: {
              location: "path",
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              required: true,
              type: "string",
            },
          },
          response: {
            $ref: "Member",
          },
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
          ],
          id: "directory.members.insert",
          flatPath: "admin/directory/v1/groups/{groupKey}/members",
          path: "admin/directory/v1/groups/{groupKey}/members",
          parameterOrder: ["groupKey"],
        },
        update: {
          response: {
            $ref: "Member",
          },
          path: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          request: {
            $ref: "Member",
          },
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
          ],
          httpMethod: "PUT",
          flatPath: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          parameterOrder: ["groupKey", "memberKey"],
          description: "Updates the membership of a user in the specified group.",
          parameters: {
            memberKey: {
              description:
                "Identifies the group member in the API request. A group member can be a user or another group. The value can be the member's (group or user) primary email address, alias, or unique ID.",
              required: true,
              type: "string",
              location: "path",
            },
            groupKey: {
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              location: "path",
              type: "string",
              required: true,
            },
          },
          id: "directory.members.update",
        },
        patch: {
          request: {
            $ref: "Member",
          },
          id: "directory.members.patch",
          response: {
            $ref: "Member",
          },
          description:
            "Updates the membership properties of a user in the specified group. This method supports [patch semantics](https://developers.google.com/workspace/admin/directory/v1/guides/performance#patch).",
          httpMethod: "PATCH",
          flatPath: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          parameterOrder: ["groupKey", "memberKey"],
          path: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
          ],
          parameters: {
            memberKey: {
              required: true,
              type: "string",
              location: "path",
              description:
                "Identifies the group member in the API request. A group member can be a user or another group. The value can be the member's (group or user) primary email address, alias, or unique ID.",
            },
            groupKey: {
              location: "path",
              required: true,
              type: "string",
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
            },
          },
        },
        delete: {
          httpMethod: "DELETE",
          flatPath: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          parameterOrder: ["groupKey", "memberKey"],
          path: "admin/directory/v1/groups/{groupKey}/members/{memberKey}",
          id: "directory.members.delete",
          description: "Removes a member from a group.",
          scopes: [
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.group.member",
          ],
          parameters: {
            groupKey: {
              required: true,
              type: "string",
              description:
                "Identifies the group in the API request. The value can be the group's email address, group alias, or the unique group ID.",
              location: "path",
            },
            memberKey: {
              required: true,
              description:
                "Identifies the group member in the API request. A group member can be a user or another group. The value can be the member's (group or user) primary email address, alias, or unique ID.",
              type: "string",
              location: "path",
            },
          },
        },
      },
    },
  },
} as const;

/** The OAuth scopes each Directory route accepts, keyed as `METHOD /path/:param`, from the methods above. */
export const directoryRouteScopes: Record<string, readonly string[]> = Object.fromEntries(
  Object.values(document.resources).flatMap((resource) =>
    Object.values(resource.methods).map((method) => [
      `${method.httpMethod} /${method.flatPath.replace(/\{(\w+)\}/g, ":$1")}`,
      method.scopes,
    ]),
  ),
);

export function buildDirectoryDiscoveryDocument(baseUrl: string) {
  const rootUrl = `${baseUrl.replace(/\/$/, "")}/`;
  return { ...document, rootUrl, baseUrl: rootUrl, servicePath: "", basePath: "", batchPath: "batch" };
}
