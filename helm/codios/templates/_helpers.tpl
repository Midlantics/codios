{{/*
Expand the name of the chart.
*/}}
{{- define "codios.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "codios.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "codios.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "codios.labels" -}}
helm.sh/chart: {{ include "codios.chart" . }}
{{ include "codios.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "codios.selectorLabels" -}}
app.kubernetes.io/name: {{ include "codios.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "codios.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "codios.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret that holds credentials.
*/}}
{{- define "codios.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "codios.fullname" . }}
{{- end }}
{{- end }}

{{/*
DATABASE_URL — prefers external DB, falls back to bundled postgresql.
*/}}
{{- define "codios.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:$(POSTGRES_PASSWORD)@%s-postgresql:5432/%s" .Values.postgresql.auth.username (include "codios.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:$(POSTGRES_PASSWORD)@%s:%d/%s" .Values.externalDatabase.user .Values.externalDatabase.host (int .Values.externalDatabase.port) .Values.externalDatabase.database }}
{{- end }}
{{- end }}

{{/*
REDIS_URL — prefers external Redis, falls back to bundled redis.
*/}}
{{- define "codios.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://:$(REDIS_PASSWORD)@%s-redis-master:6379" (include "codios.fullname" .) }}
{{- else }}
{{- printf "redis://:$(REDIS_PASSWORD)@%s:%d" .Values.externalRedis.host (int .Values.externalRedis.port) }}
{{- end }}
{{- end }}
