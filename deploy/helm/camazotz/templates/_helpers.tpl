{{- define "camazotz.labels" -}}
app.kubernetes.io/part-of: camazotz
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "camazotz.selectorLabels" -}}
app: {{ . }}
{{- end -}}
