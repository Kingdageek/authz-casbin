## Authz-Casbin

Practical example implementation of authorization in [Casbin](https://casbin.org) - an open-source, robust access-control library.
Authorization for an enterprise file-sharing SaaS platform is implemented.

**In our file-sharing platform:**

- many users, teams, departments belong to one organization
- a user can belong to one department within the organization
- a user can belong to many teams within the organization
- a user can have many assigned roles
- users create files and set permissions available to entities for their files when they share them
- files can be shared to individuals, entire teams, departments and for the entire organization

**Entities here:** *Organizations*, *Users*, *Teams*, *Roles*, *Departments*, *Files*

**Actions users can perform on files or available permissions:**

- read 
- write
- download
- delete
- share

### AuthN vs AuthZ

Authentication (AuthN) is the process of verifying credentials, that a user/entity is whom they claim to be.

Authorization (AuthZ) on the other hand, is the process of verifying what authenticated user can/cannot do. It is that process of determining access rights to digital assets or actions. This has become so commonplace in apps that there are different models/forms an authorization implementation can be:

- **Access Control Lists (ACL):** matching users directly to the entities they can access. Basically a list of a mapping of users to accessible entities and actions they can perform on those entities

- **Role-Based Access Control (RBAC):** here, users are assigned roles and those roles are mapped to a group of permissions or actions users with a role can perform. In our example file-sharing platform, a user with the role `owner` should be able to perform every allowed action for a file they can access.

- **Attribute-Based Access Control (ABAC):** here, accessed is managed based on attributes users or resources possess e.g. In our example, a user object will have `userId`, `orgId`, `roles`, `deptId` etc as attributes and we use them to make authorization more fine-grained.

### Casbin Basics

In typical authorization flows, we have a *subject* (entity) that can perform an *action* on an *object*. This is the classic `{subject, object, action}` flow. Casbin lets you specify how authorization should work using those definitions to describe access conditions, see the [model.CONF](./config/model.CONF) file.

To enforce rules in casbin, you need two configuration files:
1. **Policy:** holds a listing of the subjects, objects, and allowed actions according to your application. Casbin provides different [adapters](https://casbin.org/docs/adapters) that can allow you save this detail in different databases. The simplest way is to store this in a CSV file like we do here.

2. **Model:** contains the layout, execution, and conditions for authorization. This is defined in special syntax based on the PERM (Policy, Effect, Request, Matchers) metamodel.

We pass these files to a casbin enforcer and then use the enforce to rules for a given, actual `{subject, object, action}` request set like so:

```go
    // casbin enforcer
	e, _ := casbin.NewEnforcer(pathToModelFile, pathToPolicyFile)

	sub := "nonso"
	act := "read"
	obj := "file1"
	res, err := e.Enforce(sub, obj, act)
```

To understand the syntax/structure of the *model.CONF* file, read more [here](https://casbin.org/docs/understanding-casbin-detail#how-does-casbin-work)

Casbin can be used to implement the authorization models listed above or even a hybrid model combining elements from each of those as we've done in this example.

### Implementation Details

With the fundamentals, however brief it was, out of the way, we can move on to applying them.
