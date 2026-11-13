#!/usr/bin/env bash
# =============================================================================
#  Validación de casos de uso UNIX en QRadar  -  SIEMTEST_20261113
#
#  Ejecuta acciones inocuas y reversibles para generar los eventos de:
#    P1 UNC_202101_002  Suspicious tmp folder execution
#    P2 UNC_202203_001  Suspicious wget or curl command detected
#    P3 UNC_202109_002  Suspicious file and directory discovery
#    P4 CYB_200001_132  Multiple password changes using different accounts
#    P5 CYB_200001_135  Multiple password change failures using same account
#    P6 UNC_202606_008  Suspicious Cron command detected
#    P7 UNC_202606_007  Sudo group membership modification detected
#    P8 UNC_202606_009  User creation or modification with root privileges
#
#  Uso:   sudo bash siemtest_unix.sh
#  Log:   /root/siemtest_20261113.log  (con la hora UTC de cada prueba)
#
#  Todo se revierte al terminar, también si se interrumpe con Ctrl+C.
# =============================================================================

set -u

TAG="SIEMTEST_20261113"
USR="siemtest01"          # cuenta temporal para P4-P7
USR0="siemtest00"         # cuenta temporal UID/GID 0 para P8
BACKUP="/root/siemtest_backup"
LOG="/root/siemtest_20261113.log"
CRON_D="/etc/cron.d/siemtest_20261113"
ADMIN_GROUP=""

# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
log()   { printf '%s  %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" "$*" | tee -a "$LOG"; }
title() { echo | tee -a "$LOG"; log "=================== $* ==================="; }
warn()  { log "AVISO: $*"; }
pause() { read -rp ">> Pulsa Enter para continuar (Ctrl+C para abortar y revertir)... " _; }

# ----------------------------------------------------------------------------
# Limpieza: idempotente, se ejecuta siempre al salir
# ----------------------------------------------------------------------------
CLEANED=0
cleanup() {
  [ "$CLEANED" -eq 1 ] && return
  CLEANED=1
  title "LIMPIEZA"

  for d in /tmp /var/tmp /dev/shm; do rm -f "$d/siemtest_20261113.sh"; done

  rm -f "$CRON_D"
  if getent passwd "$USR" >/dev/null; then
    crontab -r -u "$USR" 2>/dev/null
  fi

  if getent passwd "$USR0" >/dev/null; then
    log "Borrando $USR0 (UID 0)"
    userdel -f "$USR0"
  fi

  if getent passwd "$USR" >/dev/null; then
    for g in sudo wheel; do
      if id -nG "$USR" 2>/dev/null | tr ' ' '\n' | grep -qx "$g"; then
        gpasswd -d "$USR" "$g" >/dev/null
      fi
    done
    log "Borrando $USR"
    userdel -r "$USR" 2>/dev/null
  fi

  verify
}

verify() {
  title "VERIFICACIÓN FINAL"
  local ok=1

  if getent passwd "$USR" "$USR0" >/dev/null; then
    warn "Siguen existiendo cuentas de prueba:"; getent passwd "$USR" "$USR0" | tee -a "$LOG"; ok=0
  fi

  local uid0
  uid0=$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')
  log "Cuentas con UID 0: $uid0"
  [ "$uid0" = "root " ] || { warn "Hay cuentas con UID 0 distintas de root"; ok=0; }

  if ls /tmp /var/tmp /dev/shm 2>/dev/null | grep -qi siemtest; then
    warn "Quedan ficheros siemtest en tmp"; ok=0
  fi
  if ls /var/spool/cron* /etc/cron.d 2>/dev/null | grep -qi siemtest; then
    warn "Quedan tareas cron siemtest"; ok=0
  fi

  if [ -d "$BACKUP" ]; then
    for f in passwd shadow group gshadow; do
      if ! diff -q "/etc/$f" "$BACKUP/$f" >/dev/null; then
        warn "/etc/$f difiere de la copia:"; diff "/etc/$f" "$BACKUP/$f" | tee -a "$LOG"; ok=0
      fi
    done
  fi

  pwck -r >/dev/null 2>&1 || warn "pwck -r informa de avisos (revisar manualmente)"
  grpck -r >/dev/null 2>&1 || warn "grpck -r informa de avisos (revisar manualmente)"

  if [ "$ok" -eq 1 ]; then
    log "OK: el sistema ha quedado como estaba."
    read -rp ">> ¿Borrar la copia de seguridad $BACKUP? [s/N] " r
    if [[ "$r" =~ ^[sS]$ ]]; then rm -rf "$BACKUP"; log "Copia borrada."; else log "Copia conservada en $BACKUP"; fi
  else
    warn "Revisa los avisos anteriores. La copia de los ficheros originales está en $BACKUP"
    warn "Para restaurar:  cp -a $BACKUP/{passwd,shadow,group,gshadow} /etc/"
  fi
  log "Log completo en $LOG"
}

trap cleanup EXIT
trap 'echo; warn "Interrumpido por el usuario"; exit 130' INT TERM

# ----------------------------------------------------------------------------
# Comprobaciones previas
# ----------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecuta el script como root:  sudo bash $0"; CLEANED=1; exit 1
fi

: > "$LOG"; chmod 600 "$LOG"
title "PREPARACIÓN  ($TAG)"
log "Servidor: $(hostname)   Usuario: ${SUDO_USER:-root}"

if getent passwd "$USR" "$USR0" >/dev/null; then
  echo "Ya existe $USR o $USR0. Revisa antes de continuar."; CLEANED=1; exit 1
fi

read -rp ">> Vas a ejecutar las pruebas en $(hostname). ¿Continuar? [s/N] " r
[[ "$r" =~ ^[sS]$ ]] || { CLEANED=1; exit 0; }

if systemctl is-active --quiet auditd 2>/dev/null; then
  log "auditd activo"
  auditctl -l 2>/dev/null | grep -qi execve \
    && log "Hay reglas auditd para execve" \
    || warn "No se ven reglas auditd para execve: P1-P3 podrían no generar evento"
else
  warn "auditd no está activo: P1-P3 podrían no generar evento"
fi

if getent group sudo >/dev/null; then ADMIN_GROUP="sudo"
elif getent group wheel >/dev/null; then ADMIN_GROUP="wheel"; warn "No existe grupo 'sudo'; se usará 'wheel' en P7 (confirmar con el SOC)"
fi

mkdir -m 700 -p "$BACKUP"
cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow "$BACKUP/" || { warn "No se pudo hacer la copia"; CLEANED=1; exit 1; }
log "Copia de passwd/shadow/group/gshadow en $BACKUP"

echo
echo "  RECOMENDADO: abre ahora una segunda sesión root en otra ventana y"
echo "  mantenla abierta hasta el final, por si hubiera que restaurar algo."
pause

# ----------------------------------------------------------------------------
# P1 - Ejecución desde carpetas temporales
# ----------------------------------------------------------------------------
title "P1  UNC_202101_002  Ejecución desde tmp"
for d in /tmp /var/tmp /dev/shm; do
  f="$d/siemtest_20261113.sh"
  printf '#!/bin/sh\necho %s\n' "$TAG" > "$f"
  chmod 700 "$f"
  log "Ejecutando $f"
  "$f" >/dev/null 2>&1 && log "  ejecutado" || warn "  no se pudo ejecutar (¿montado con noexec?)"
  rm -f "$f"
done

# ----------------------------------------------------------------------------
# P2 - wget y curl contra localhost
# ----------------------------------------------------------------------------
title "P2  UNC_202203_001  wget y curl"
if command -v wget >/dev/null; then
  log "wget -q -O /dev/null http://127.0.0.1/$TAG"
  wget -q -O /dev/null "http://127.0.0.1/$TAG" 2>/dev/null
else warn "wget no está instalado (no se instala)"; fi
if command -v curl >/dev/null; then
  log "curl -s -o /dev/null http://127.0.0.1/$TAG"
  curl -s -o /dev/null "http://127.0.0.1/$TAG" 2>/dev/null
else warn "curl no está instalado (no se instala)"; fi

# ----------------------------------------------------------------------------
# P3 - Descubrimiento de ficheros
# ----------------------------------------------------------------------------
title "P3  UNC_202109_002  find -name"
log "find /tmp -maxdepth 1 -name '${TAG}*'"
find /tmp -maxdepth 1 -name "${TAG}*" >/dev/null

# ----------------------------------------------------------------------------
# Cuenta temporal
# ----------------------------------------------------------------------------
title "Creando cuenta temporal $USR"
useradd -m -d "/home/$USR" -c "$TAG" -s /bin/bash "$USR" || { warn "No se pudo crear $USR"; exit 1; }
log "Cuenta $USR creada"

# ----------------------------------------------------------------------------
# P4 - Cambio de contraseña correcto
# ----------------------------------------------------------------------------
title "P4  CYB_200001_132  Cambio de contraseña correcto"
echo "  Introduce dos veces una contraseña robusta para $USR."
echo "  APÚNTALA: la necesitas en P5 (solo durante la prueba)."
until passwd "$USR"; do warn "No se cambió, vuelve a intentarlo"; done
log "Contraseña de $USR cambiada"

# ----------------------------------------------------------------------------
# P5 - Cambio de contraseña fallido
# ----------------------------------------------------------------------------
title "P5  CYB_200001_135  Cambio de contraseña fallido"
echo "  Se ejecutará 'passwd' como $USR."
echo "  En 'Current password' escribe una contraseña INCORRECTA (una sola vez)."
pause
su - "$USR" -c passwd && warn "El cambio no falló: revisa" || log "Intento fallido de cambio de contraseña generado"

# ----------------------------------------------------------------------------
# P6 - Tarea cron que referencia /tmp
# ----------------------------------------------------------------------------
title "P6  UNC_202606_008  Comando cron"
CRON_CMD="ls /tmp > /dev/null 2>&1"
if [ -f /etc/cron.allow ] && ! grep -qx "$USR" /etc/cron.allow; then
  log "cron.allow restringe usuarios: se usa $CRON_D"
  echo "* * * * * $USR $CRON_CMD # $TAG" > "$CRON_D"; chmod 644 "$CRON_D"
else
  echo "* * * * * $CRON_CMD # $TAG" | crontab -u "$USR" -
  log "Crontab de $USR: $CRON_CMD"
fi
log "Esperando 130 s a que cron ejecute la tarea..."
sleep 130
crontab -r -u "$USR" 2>/dev/null; rm -f "$CRON_D"
log "Tarea cron eliminada"

# ----------------------------------------------------------------------------
# P7 - Alta y baja en el grupo sudo
# ----------------------------------------------------------------------------
title "P7  UNC_202606_007  Grupo ${ADMIN_GROUP:-sudo}"
if [ -n "$ADMIN_GROUP" ]; then
  usermod -L "$USR"
  log "Cuenta $USR bloqueada antes del cambio de grupo"
  usermod -aG "$ADMIN_GROUP" "$USR" && log "usermod -aG $ADMIN_GROUP $USR  -> $(id "$USR")"
  gpasswd -d "$USR" "$ADMIN_GROUP" >/dev/null && log "Revertido -> $(id "$USR")"
else
  warn "No existe grupo sudo ni wheel: P7 no se ejecuta"
fi

# ----------------------------------------------------------------------------
# P8 - Cuenta con UID/GID 0 (sin contraseña, nologin, sin home)
# ----------------------------------------------------------------------------
title "P8  UNC_202606_009  Cuenta con UID/GID 0"
echo "  Se creará $USR0 con UID/GID 0, bloqueada y sin shell, y se borrará en el acto."
pause
useradd -o -u 0 -g 0 -M -d /nonexistent -s /sbin/nologin -c "$TAG" "$USR0" \
  && log "Creada: $(getent passwd "$USR0")"
userdel -f "$USR0"
if getent passwd "$USR0" >/dev/null; then
  warn "$USR0 NO se ha borrado. Restaura con:  cp -a $BACKUP/{passwd,shadow,group,gshadow} /etc/"
else
  log "$USR0 borrada"
fi

title "PRUEBAS TERMINADAS"
log "Avisa al SOC del fin de la ventana y comparte $LOG"
# La limpieza y la verificación se ejecutan automáticamente al salir (trap EXIT)
