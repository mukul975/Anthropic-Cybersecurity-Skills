---
name: implementing-rbac-for-kubernetes-cluster
description: Implement RBAC in Kubernetes with least-privilege roles, service accounts, and audit policies.
domain: cybersecurity
subdomain: container-security
tags: [kubernetes, rbac, access-control, container-security, least-privilege]
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---

# Implementación de RBAC en Kubernetes

## Descripción General

El Control de Acceso Basado en Roles (RBAC) en Kubernetes permite definir permisos granulares para usuarios, grupos y cuentas de servicio, implementando políticas de mínimo privilegio.

## Prerrequisitos

- Clúster Kubernetes 1.26+ con RBAC habilitado
- kubectl con permisos de administrador
- Herramientas: `kubectl auth can-i`, `rakkess`

## Pasos

1. Auditar permisos existentes con `kubectl get clusterrolebindings`
2. Identificar cuentas con permisos excesivos
3. Crear Roles con mínimo privilegio por carga de trabajo
4. Configurar RoleBindings apropiados
5. Implementar auditoría de accesos
6. Validar con `kubectl auth can-i --list`

## Resultado Esperado

Clúster con RBAC de mínimo privilegio, ServiceAccounts seguros y auditoría activa.
