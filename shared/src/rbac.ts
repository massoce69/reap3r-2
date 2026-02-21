// ─────────────────────────────────────────────
// MASSVISION Reap3r — RBAC (Roles & Permissions)
// ─────────────────────────────────────────────

export enum Permission {
  // Dashboard
  DashboardView = 'dashboard:view',

  // Companies
  CompanyList = 'company:list',
  CompanyView = 'company:view',
  CompanyCreate = 'company:create',
  CompanyUpdate = 'company:update',
  CompanyDelete = 'company:delete',

  // Folders
  FolderList = 'folder:list',
  FolderView = 'folder:view',
  FolderCreate = 'folder:create',
  FolderUpdate = 'folder:update',
  FolderDelete = 'folder:delete',

  // Agents
  AgentList = 'agent:list',
  AgentView = 'agent:view',
  AgentDelete = 'agent:delete',
  AgentMove = 'agent:move',
  AgentEnroll = 'agent:enroll',
  AgentUpdate = 'agent:update',

  // Jobs
  JobList = 'job:list',
  JobView = 'job:view',
  JobCreate = 'job:create',
  JobCancel = 'job:cancel',
  JobRunScript = 'job:run_script',
  JobReboot = 'job:reboot',
  JobShutdown = 'job:shutdown',

  // Remote
  RemoteShell = 'remote:shell',
  RemoteDesktop = 'remote:desktop',
  RemotePrivacyMode = 'remote:privacy_mode',
  RemoteInputLock = 'remote:input_lock',
  RemotePower = 'remote:power',
  RemoteWakeOnLan = 'remote:wake_on_lan',

  // Enrollment
  TokenCreate = 'token:create',
  TokenList = 'token:list',
  TokenRevoke = 'token:revoke',

  // Audit
  AuditView = 'audit:view',

  // Users / Admin
  UserList = 'user:list',
  UserView = 'user:view',
  UserCreate = 'user:create',
  UserUpdate = 'user:update',
  UserSuspend = 'user:suspend',
  UserResetMfa = 'user:reset_mfa',

  // Teams
  TeamList = 'team:list',
  TeamCreate = 'team:create',
  TeamUpdate = 'team:update',
  TeamDelete = 'team:delete',

  // Roles
  RoleList = 'role:list',
  RoleCreate = 'role:create',
  RoleUpdate = 'role:update',
  RoleDelete = 'role:delete',

  // Policies
  PolicyView = 'policy:view',
  PolicyUpdate = 'policy:update',

  // Vault / Secrets
  SecretList = 'secret:list',
  SecretRead = 'secret:read',
  SecretWrite = 'secret:write',
  SecretDelete = 'secret:delete',
  SecretUse = 'secret:use',
  SecretReveal = 'secret:reveal',

  // Messaging
  MessageRead = 'message:read',
  MessageWrite = 'message:write',
  ChannelManage = 'channel:manage',

  // EDR / SOC
  EdrEventsView = 'edr:events_view',
  EdrDetectionsView = 'edr:detections_view',
  EdrRespond = 'edr:respond',
  EdrPolicyManage = 'edr:policy_manage',
  EdrIncidentManage = 'edr:incident_manage',
  EdrHunt = 'edr:hunt',

  // Artifacts
  ArtifactUpload = 'artifact:upload',
  ArtifactDownload = 'artifact:download',

  // Settings
  SettingsView = 'settings:view',
  SettingsUpdate = 'settings:update',

  // Deployment
  DeploymentView = 'deployment:view',
  DeploymentCreate = 'deployment:create',
  DeploymentExecute = 'deployment:execute',
  DeploymentCancel = 'deployment:cancel',

  // Alerting
  AlertRuleList = 'alert:rule_list',
  AlertRuleCreate = 'alert:rule_create',
  AlertRuleUpdate = 'alert:rule_update',
  AlertRuleDelete = 'alert:rule_delete',
  AlertEventList = 'alert:event_list',
  AlertEventAck = 'alert:event_ack',
  AlertEventResolve = 'alert:event_resolve',
  AlertEventSnooze = 'alert:event_snooze',
  AlertIntegrationManage = 'alert:integration_manage',
  AlertTest = 'alert:test',
}

export enum Role {
  SuperAdmin = 'super_admin',
  OrgAdmin = 'org_admin',
  Operator = 'operator',
  Viewer = 'viewer',
  SocAnalyst = 'soc_analyst',
}

const allPerms = Object.values(Permission);

export const RolePermissions: Record<Role, Permission[]> = {
  [Role.SuperAdmin]: allPerms,

  [Role.OrgAdmin]: allPerms.filter((p) => p !== Permission.SettingsUpdate),

  [Role.Operator]: [
    Permission.DashboardView,
    Permission.AgentList, Permission.AgentView, Permission.AgentMove, Permission.AgentUpdate,
    Permission.JobList, Permission.JobView, Permission.JobCreate, Permission.JobCancel,
    Permission.JobRunScript, Permission.JobReboot, Permission.JobShutdown,
    Permission.RemoteShell, Permission.RemoteDesktop, Permission.RemotePower,
    Permission.RemoteWakeOnLan,
    Permission.CompanyList, Permission.CompanyView,
    Permission.FolderList, Permission.FolderView,
    Permission.TokenList,
    Permission.AuditView,
    Permission.UserList, Permission.UserView,
    Permission.SecretList, Permission.SecretRead, Permission.SecretUse,
    Permission.MessageRead, Permission.MessageWrite,
    Permission.EdrEventsView, Permission.EdrDetectionsView,
    Permission.ArtifactUpload, Permission.ArtifactDownload,
    Permission.DeploymentView, Permission.DeploymentCreate, Permission.DeploymentExecute, Permission.DeploymentCancel,
    Permission.AlertRuleList, Permission.AlertEventList, Permission.AlertEventAck,
  ],

  [Role.Viewer]: [
    Permission.DashboardView,
    Permission.AgentList, Permission.AgentView,
    Permission.CompanyList, Permission.CompanyView,
    Permission.FolderList, Permission.FolderView,
    Permission.JobList, Permission.JobView,
    Permission.AuditView,
    Permission.UserList, Permission.UserView,
    Permission.EdrEventsView, Permission.EdrDetectionsView,
    Permission.MessageRead,
    Permission.DeploymentView,
  ],

  [Role.SocAnalyst]: [
    Permission.DashboardView,
    Permission.AgentList, Permission.AgentView,
    Permission.CompanyList, Permission.CompanyView,
    Permission.FolderList, Permission.FolderView,
    Permission.JobList, Permission.JobView, Permission.JobCreate,
    Permission.AuditView,
    Permission.EdrEventsView, Permission.EdrDetectionsView,
    Permission.EdrRespond, Permission.EdrIncidentManage,
    Permission.MessageRead, Permission.MessageWrite,
    Permission.SecretList, Permission.SecretRead,
    Permission.DeploymentView,
    Permission.AlertRuleList, Permission.AlertEventList,
    Permission.AlertEventAck, Permission.AlertEventResolve, Permission.AlertEventSnooze,
  ],
};
