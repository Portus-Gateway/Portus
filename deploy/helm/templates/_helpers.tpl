{{/*
Expand the name of the chart.
*/}}
{{- define "portus-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "portus-gateway.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "portus-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "portus-gateway.labels" -}}
helm.sh/chart: {{ include "portus-gateway.chart" . }}
{{ include "portus-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "portus-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portus-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "portus-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "portus-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image references: the tag defaults to the chart's appVersion so a chart
version pins the images it was released with.
*/}}
{{- define "portus-gateway.controllerImage" -}}
{{- printf "%s:%s" .Values.controller.image.repository (default .Chart.AppVersion .Values.controller.image.tag) }}
{{- end }}

{{- define "portus-gateway.dataplaneImage" -}}
{{- printf "%s:%s" .Values.dataplane.image.repository (default .Chart.AppVersion .Values.dataplane.image.tag) }}
{{- end }}

{{/*
The controller's gRPC Service name and the mTLS Secret for the config stream:
the user's Secret when grpcTls.secretName is set, otherwise the one the chart
generates (templates/grpc-tls-secret.yaml).
*/}}
{{- define "portus-gateway.controllerServiceName" -}}
{{- printf "%s-controller" (include "portus-gateway.fullname" .) }}
{{- end }}

{{- define "portus-gateway.grpcTlsSecretName" -}}
{{- default (printf "%s-grpc-tls" (include "portus-gateway.fullname" .)) .Values.grpcTls.secretName }}
{{- end }}
