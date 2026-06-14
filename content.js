(async function () {
  const CONFIG = {
    URL_PATTERN: "administration-etrangers-en-france",
    TAB_NAME: "Demande d'accès à la Nationalité Française",
    API_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/dossier-stepper",
    API_DOSSIER_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/usager/dossiers/",
    WAIT_TIME: 100,
    API_RETRY_DELAY: 3000,
    API_MAX_RETRIES: 10,
  };

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function fetchStepperWithRetry() {
    let lastStatus = null;

    for (let attempt = 1; attempt <= CONFIG.API_MAX_RETRIES; attempt++) {
      try {
        const response = await fetch(CONFIG.API_ENDPOINT, {
          credentials: "include",
        });

        if (response.status === 404 || response.status === 204) {
          return null;
        }

        if (!response.ok) {
          lastStatus = response.status;
          if (attempt < CONFIG.API_MAX_RETRIES) {
            console.warn(
              `Extension API Naturalisation : stepper HTTP ${response.status} (tentative ${attempt}/${CONFIG.API_MAX_RETRIES}), nouvel essai dans 3s`
            );
            await sleep(CONFIG.API_RETRY_DELAY);
            continue;
          }
          break;
        }

        return response;
      } catch (error) {
        lastStatus = "network";
        if (attempt < CONFIG.API_MAX_RETRIES) {
          console.warn(
            `Extension API Naturalisation : stepper inaccessible (tentative ${attempt}/${CONFIG.API_MAX_RETRIES}), nouvel essai dans 3s:`,
            error
          );
          await sleep(CONFIG.API_RETRY_DELAY);
          continue;
        }
        console.warn(
          "Extension API Naturalisation : API stepper inaccessible après 10 tentatives:",
          error
        );
        return null;
      }
    }

    if (lastStatus === 401) {
      console.warn(
        "Extension API Naturalisation : API stepper 401 — session non authentifiée (connectez-vous sur ANEF ou attendez le chargement complet)"
      );
    } else if (lastStatus) {
      console.warn(
        `Extension API Naturalisation : API stepper échouée après ${CONFIG.API_MAX_RETRIES} tentatives (HTTP ${lastStatus})`
      );
    }

    return null;
  }

  // Extension version from manifest.json
  const extensionVersion = "3.1";
  console.log(`Extension API Naturalisation - Version: ${extensionVersion}`);

  // Fonction de décryptage dédiée à Kamal : Round 2
  function IamKamal_23071993_v2(encryptedData) {
    const rsaKey = {
      privateKeyPem:
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/WvhR9YrO6DHY\n0UpAoIlIuDoF3PtLEJ3J0T5FOLAPSY2sa33AnECl6jWfM7uLuojuTDbfIz6J3vAo\nsNUzwYFNHKx3EG1o6cYzjWm2LzZDa4e25wYlXcL2r3T0mFGS9DT7adKlomNURj4L\nf2WUt11oNH8RYyH/uNk+kIL0HRJLtfTjyyjlWSyjUUDD1ATYZwjnQS2HvdcqJ+Go\n3TTvqTG7yOPzC/lwSKG3zE3eL+pi9E9Lgw9NlSanewOu7toB9NiKwzP3kfSBNpkz\nSv4UBNClfp1UG+psSPnTx3Csil9TbPjSe99ZZ0/ffPf0h2xoga/7rWgScQwHzN9E\ncrvEfDgxAgMBAAECggEAa08Ikm2wOffcfEph6XwdgLpPT5ptEdtvoQ3GbessUGZf\nHKHrE2iMmH6PM4g/VEx3Hat/2gJZv9dVtnv0E+IgMK4zyVFdCciPbbmP3qr7MzPK\nF7fWqn26J7ydSc1hcZehXpwplNlL+qaphKkcvhlWOGm4GHgPSOjQa1V/GoZzDCE1\ne1z9KpVuMMiV4d89FFiE3MHtnrmMnmUdbnesffVftnPmzkkGKKWTCL1BLrdEXgCz\nGSFdqCo+PjcJjEojjmqHhgzTyjPOR6JGh0FqG9ht3aduIQMZfKR1p2+Ds18NlOZu\nT60Lyc7Ud/d0H0f2h9GfftHYCSLkIxfTaAmoYXzXAQKBgQDoWc91xlh8Kb3vmIN1\nIoVY2yhviDTpUqkGxvjt6WYmu38CFpEwSO0cpTVCAkWRKvjKLUOoCAaqfaTrN04t\nLG85Z18gvSQKmncfv0zrKaTN/FrnKOA//hPCAcveDT6Ir9SCxgVmNBox70k89eQ+\n5cDOZACqFhKcoAQa/LjF621HBQKBgQDS1Pi+GhSwbn6nBiqQdzU1+RpXdburzubd\n3dgNlrAOmLoFEGqYNzaMcKbNljNTnAdv/FX6/NYaQGx/pYTs26o/SZZ+SE7Cl2RS\nRJIuWeskuNEoH4W06JgO1djyHVOiHmKbyaATWCjoZSQnnHo8OUBUKOJpw8mrNlQl\nIYUE0OLcPQKBgQDD3LlKUZnTiKhoqYrfGeuIfK34Xrwjlx+O6/l5LA+FRPaKfxWC\nu2bNh+J+M0YLWksAuulWYvWjkGiOMz++Sr+zhxUkluwj2BPk+jDP53nafgju5YEr\n0HU9TKBbHZUCSh384wo4HmGaiFiXf7wY3ToLgTciKZsk1qq/SRxFEvE6NQKBgHcS\nCs2qgybFsMf55o4ilS2/Ww4sEurMdny1bvD1usbzoJN9mwYOoMMeWEZh3ukIhPbN\nJ24R34WB/wT0YSc4RGVr1Q/LHJgv0lvYGEsPQ4tAyfeEHgp3FnHCerz6rSIxUPW1\nIK/sKWZewNWSPULH/rnJQV4EUmBc1ZcG4E5A/u7tAoGBAMneO96PMhJFQDhsakTL\nvGTbhuwBnFjbSuxmyebhszASOuKm8XTVDe004AZTSy7lAm+iYTkfeRbfVrIGWElT\n5DWhmlN/zNTdX56dQWG3P5M48+bxZFXz0YCBAZJw8jZ5LcFuKrr5tQbcNZN9Pqgk\nQJNdXtE3G7SjkDOn36yZSaXp\n-----END PRIVATE KEY-----",
      passphrase: "wa_sir_3awtani_Dir_l_bou9_aaa_khay_div",
      responsephrase: "nta khassek douz f télé, barnamaj : ne7ki hmoumi",
    };

    const extractFormData = function (data) {
      var parts = data.split("#K#");
      if (parts.length) {
        return parts[0];
      } else {
        return null;
      }
    };
    try {
      var privateKey = forge.pki.decryptRsaPrivateKey(
        rsaKey.privateKeyPem.trim(),
        rsaKey.passphrase
      );
      if (!privateKey) {
        throw new Error(
          "Échec de décryptage de la clé privée. Vérifiez la passphrase."
        );
      }
      var decodedData = forge.util.decode64(encryptedData);
      var buffer = forge.util.createBuffer(decodedData, "raw");
      var decryptedData = privateKey.decrypt(buffer.getBytes(), "RSA-OAEP", {
        md: forge.md.sha256.create(),
        mgf1: forge.md.sha256.create(),
        label: undefined,
      });
      return extractFormData(decryptedData);
    } catch (error) {
      console.error("Erreur de décryptage :", error);
      return null;
    }
  }

  if (!window.location.href.includes(CONFIG.URL_PATTERN)) return;

  function getStatusDescription(status) {
    const statusMap = {
        // 0 Brouillon
        draft: "Dossier en brouillon",
        // 1 Dépôt de la demande
        dossier_depose: "Dossier déposé",
        // 2 Examen des pièces en cours
        verification_formelle_a_traiter: "Préfecture : Vérification à traiter",
        verification_formelle_en_cours:
          "Préfecture : Vérification formelle en cours",
        verification_formelle_mise_en_demeure:
          "Préfecture : Vérification formelle, mise en demeure",
        instruction_a_affecter:
          "Préfecture : En attente affectation à un agent",
        // 3 Réception du récépissé de complétude
        instruction_recepisse_completude_a_envoyer:
          "Préfecture : récépissé de complétude à envoyer",
        instruction_recepisse_completude_a_envoyer_retour_complement_a_traiter:
          "Préfecture : Compléments à vérfier par l'agent",
        // 4 Entretien
        instruction_date_ea_a_fixer: "Préfecture : Date entretien à fixer",
        ea_demande_report_ea: "Préfecture : Demande de report entretien",
        ea_en_attente_ea: "Préfecture : Attente convocation entretien",
        ea_crea_a_valider:
          "Préfecture : Entretien passé, compte-rendu à valider",
        // 5 Decision prefecture
        prop_decision_pref_a_effectuer: "Préfecture : Décision à effectuer",
        prop_decision_pref_en_attente_retour_hierarchique:
          "Préfecture : En attente retour hiérarchique",
        prop_decision_pref_en_attente_retour_hierarchiqu:
          "Préfecture : En attente retour hiérarchique",
        prop_decision_pref_prop_a_editer:
          "Préfecture : Décision prise, rédaction en cours",
        prop_decision_pref_en_attente_retour_signataire:
          "Préfecture : En attente retour signataire",
        // 6 Controle
        controle_a_affecter: "SDANF : Dossier transmis, attente d'affectation",
        controle_a_effectuer: "SDANF : Contrôle état civil à effectuer",
        controle_en_attente_pec: "SCEC : Attente validation pièce d'état civil",
        controle_pec_a_faire: "SCEC : Validation en cours pièce d'état civil",
        controle_transmise_pour_decret:
          "SDANF : Décret transmis pour approbation",
        controle_en_attente_retour_hierarchique:
          "SDANF : Attente retour hiérarchique pour décret",
        controle_decision_a_editer:
          "SDANF : Décision hiérarchique prise, édition prochaine",
        controle_en_attente_signature:
          "SDANF : Décision prise, attente signature",
        controle_demande_notifiee: "Contrôle : demande notifiée",
        // 7 Traitement en cours
        transmis_a_ac: "Décret : Dossier transmis au service décret",
        a_verifier_avant_insertion_decret:
          "Décret : Vérification avant insertion décret",
        prete_pour_insertion_decret:
          "Décret : Dossier prêt pour insertion décret",
        inseree_dans_decret: "Décret : Demande insérée dans décret",
        decret_envoye_prefecture: "Décret envoyé à préfecture",
        notification_envoyee: "Décret : Notification envoyée au demandeur",
        demande_traitee: "Décret : Demande finalisée",
        // 8 Décision
        decret_naturalisation_publie:
          "Décision : Décret de naturalisation publié",
        decret_en_preparation: "Décision : Décret en préparation",
        decret_a_qualifier: "Décision : Décret à qualifier",
        decret_en_validation: "Décision : Décret en validation",
        decision_negative_en_delais_recours:
          "Décision négative en délais de recours",
        irrecevabilite_manifeste: "Décision : irrecevabilité manifeste",
        irrecevabilite_manifeste_en_delais_recours:
          "Décision : irrecevabilité en délais de recours",
        decision_notifiee: "Décision notifiée",
        demande_en_cours_rapo: "Décision : Demande en cours RAPO",
        controle_demande_notifiee: "Décision : Contrôle demande notifiée",
        decret_publie: "Décret de naturalisation publié",
        // 9 CSS
        css_en_delais_recours: "Classement sans suite en délais de recours",
        css_notifie: "Classement sans suite notifiée",
        css_mise_en_demeure_a_affecter:
          "Classement sans suite, Mise en demeure à affecter",
        css_manuels_a_affecter:
          "Proposition de Classement sans suite manuels à affecter",
        css_manuels_a_rediger:
          "Proposition de Classement sans suite manuels à rédiger",
        css_mise_en_demeure_a_rediger:
          "Classement sans suite, Mise en demeure à rédiger",
        css_automatiques_a_affecter:
          "Classement sans suite automatiques à affecter",
        css_automatiques_a_rediger:
          "Proposition de Classement sans suite automatiques à rédiger",
        //
        prenat_a_traiter: "Prenaturalisation : À traiter",
        prenat_en_cours: "Prenaturalisation : En cours",
        prenat_en_attente_complements:
          "Prenaturalisation : En attente compléments",
        prenat_cloture: "Prenaturalisation : Clôturée",
        //
        scec_a_faire: "SCEC à faire",
        scec_en_cours: "SCEC en cours",
        scec_en_attente: "SCEC en attente",
        scec_bloque: "SCEC bloqué",
        scec_termine: "SCEC terminé",
        non_applicable: "SCEC non attribuable",
        //
        code_non_reconnu: "Code non reconnu",
      };

    return statusMap[status] || status || statusMap["code_non_reconnu"];
  }

  function daysAgo(dateString) {
      const inputDate = new Date(dateString);
      const currentDate = new Date();
      const diffInDays = Math.floor(
        (currentDate - inputDate) / (1000 * 60 * 60 * 24)
      );

      if (diffInDays === 0) {
        const hours = String(inputDate.getHours()).padStart(2, "0");
        const minutes = String(inputDate.getMinutes()).padStart(2, "0");
        return `Aujourd'hui à ${hours}h${minutes}`;
      }
      if (diffInDays === 1) {
        const hours = String(inputDate.getHours()).padStart(2, "0");
        const minutes = String(inputDate.getMinutes()).padStart(2, "0");
        return `Hier à ${hours}h${minutes}`;
      }
      if (diffInDays <= 30) return `il y a ${diffInDays} jrs`;

      const years = Math.floor(diffInDays / 365);
      const months = Math.floor((diffInDays % 365) / 30);
      const days = diffInDays % 30;

      if (years >= 1) {
        if (months === 0) {
          return `il y a ${years} ${years === 1 ? "an" : "ans"}`;
        }
        return `il y a ${years} ${
          years === 1 ? "an" : "ans"
        } et ${months} mois`;
      }

      if (months >= 1) {
        if (days === 0) {
          return `il y a ${months} ${months === 1 ? "mois" : "mois"}`;
        }
        return `il y a ${months} ${
          months === 1 ? "mois" : "mois"
        } et ${days} jrs`;
      }

      return `il y a ${months} mois`;
    }

  function formatDate(dateString) {
    if (!dateString) return "";
    const d = new Date(dateString);
    if (isNaN(d)) return "";
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = String(d.getFullYear());
    return `${dd}/${mm}/${yyyy}`;
  }

  function hasNaturalisationData(apiInfos) {
    if (!apiInfos?.idDossier || !apiInfos?.dossier?.statut) return false;

    const code = String(apiInfos.statutCode || "").trim();
    if (!code || code === "-" || code.toLowerCase() === "code_non_reconnu") {
      return false;
    }

    return Boolean(apiInfos.statutDescription);
  }

  function removeStepperIfPresent() {
    document.getElementById("anf-extension-stepper-root")?.remove();
  }

  async function fetchApiInfos() {
    const response = await fetchStepperWithRetry();
    if (!response) return null;

    let dossierData;
    try {
      dossierData = await response.json();
    } catch {
      return null;
    }

    if (!dossierData?.dossier?.id || !dossierData?.dossier?.statut) {
      return null;
    }

    const data = { dossier: dossierData.dossier };
    const idDossier = dossierData.dossier.id;
    const dossierStatusCode = IamKamal_23071993_v2(data.dossier.statut);
    if (
      !dossierStatusCode ||
      dossierStatusCode === "-" ||
      String(dossierStatusCode).trim() === ""
    ) {
      return null;
    }

    const dossierStatus = getStatusDescription(
      String(dossierStatusCode).toLowerCase()
    );

    return {
      version: extensionVersion,
      idDossier,
      statutCode: dossierStatusCode,
      statutDescription: dossierStatus,
      dateStatut: data.dossier.date_statut,
      dateStatutRelative: daysAgo(data.dossier.date_statut),
      demandeDate: null,
      complementInstructionDate: null,
      assimilationDate: null,
      assimilationPlateforme: null,
      recepisseCreated: null,
      decretId: null,
      dossier: data.dossier,
      dossierDetails: null,
      notifications: [],
      raw: {
        stepper: dossierData,
        dossier: null,
        notifications: [],
      },
    };
  }

  async function enrichApiInfos(apiInfos) {
    const idDossier = apiInfos.idDossier;
    const [dossierRaw, notifRaw] = await Promise.all([
      fetch(CONFIG.API_DOSSIER_ENDPOINT + idDossier)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      fetch(
        "https://administration-etrangers-en-france.interieur.gouv.fr/api/notifications"
      )
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ]);

    if (dossierRaw) {
      const dossierDetails = dossierRaw?.data ?? dossierRaw;
      apiInfos.dossierDetails = dossierDetails;
      apiInfos.raw.dossier = dossierDetails;
      apiInfos.demandeDate =
        dossierDetails?.taxe_payee?.date_consommation || null;
      apiInfos.assimilationDate =
        dossierDetails?.entretien_assimilation?.date_rdv || null;
      apiInfos.assimilationPlateforme =
        dossierDetails?.entretien_assimilation?.unite_gestion?.nom_plateforme ||
        null;

      const idents =
        dossierDetails?.demande?.informations?.etat_civil?.identites_decrets;
      if (Array.isArray(idents) && idents.length > 0) {
        for (const identite of idents) {
          if (identite?.decret?.id) {
            apiInfos.decretId = identite.decret.id;
            break;
          }
        }
      }

      const demandeComplements = dossierDetails?.demande_complement;
      if (Array.isArray(demandeComplements) && demandeComplements.length > 0) {
        const complementInstructions = demandeComplements.filter(
          (dc) => dc?.type_complement === "COMPLEMENT_INSTRUCTION"
        );
        if (complementInstructions.length > 0) {
          apiInfos.complementInstructionDate = complementInstructions.sort(
            (a, b) =>
              new Date(b.date_creation_demande) -
              new Date(a.date_creation_demande)
          )[0]?.date_creation_demande;
        }
      }
    }

    if (notifRaw) {
      apiInfos.notifications = Array.isArray(notifRaw?._items)
        ? notifRaw._items
        : [];
      apiInfos.raw.notifications = apiInfos.notifications;
      const matches = apiInfos.notifications.filter(
        (it) =>
          String(it?.id_demande) === String(idDossier) &&
          it?.type_notification === "NATIONALITE" &&
          it?.motif_notification === "RECEPISSE_COMPLETUDE_ENVOYE"
      );
      if (matches.length) {
        apiInfos.recepisseCreated = matches.sort(
          (a, b) => new Date(b._created) - new Date(a._created)
        )[0]?._created;
      }
    }

    return apiInfos;
  }

  function logApiInfos(apiInfos) {
    window.__ANF_API_INFOS__ = apiInfos;

    console.group(
      `Extension API Naturalisation v${apiInfos.version} — Infos API`
    );
    console.log("Statut code:", apiInfos.statutCode);
    console.log("Statut description:", apiInfos.statutDescription);
    console.log("Date statut:", apiInfos.dateStatut, `(${apiInfos.dateStatutRelative})`);
    console.log("ID dossier:", apiInfos.idDossier);
    console.log("Date demande:", apiInfos.demandeDate || "—");
    console.log("Complément instruction:", apiInfos.complementInstructionDate || "—");
    console.log("Entretien assimilation:", apiInfos.assimilationDate || "—");
    if (apiInfos.assimilationPlateforme) {
      console.log("Plateforme assimilation:", apiInfos.assimilationPlateforme);
    }
    console.log("Récépissé complétude:", apiInfos.recepisseCreated || "—");
    console.log("N° décret:", apiInfos.decretId || "—");
    console.log("Résumé:", {
      statutCode: apiInfos.statutCode,
      statutDescription: apiInfos.statutDescription,
      dateStatut: apiInfos.dateStatut,
      idDossier: apiInfos.idDossier,
      decretId: apiInfos.decretId,
    });
    console.log("Données brutes (stepper):", apiInfos.raw.stepper);
    console.log("Données brutes (dossier):", apiInfos.raw.dossier);
    console.log("Données brutes (notifications):", apiInfos.raw.notifications);
    console.log(
      "Accès rapide console: tapez __ANF_API_INFOS__ pour revoir toutes les infos"
    );
    console.groupEnd();
  }

  const RECREATED_TRACKING_STEPS = [
    { key: "demande_envoyee", title: "Demande envoyée" },
    { key: "examen_pieces", title: "Examen des pièces en cours" },
    { key: "demande_deposee", title: "Demande déposée" },
    { key: "traitement_plateforme_1", title: "Traitement en cours (Plateforme)" },
    { key: "recepisse_completude", title: "Réception du récépissé de complétude" },
    { key: "traitement_plateforme_2", title: "Traitement en cours (Plateforme)" },
    { key: "entretien_assimilation", title: "Entretien d'assimilation" },
    { key: "traitement_plateforme_3", title: "Traitement en cours (Plateforme)" },
    { key: "traitement_sdanf_1", title: "Traitement en cours (SDANF)" },
    { key: "traitement_scec", title: "Traitement en cours (SCEC)" },
    { key: "traitement_sdanf_2", title: "Traitement en cours (SDANF)" },
    { key: "decision_prise", title: "Décision prise" },
    { key: "ceremonie_naturalisation", title: "Cérémonie de naturalisation" },
  ];

  function createStepIcon(stepKey) {
    const iconByStep = {
      demande_envoyee: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M22 2 11 13"></path><path d="m22 2-7 20-4-9-9-4 20-7Z"></path></svg>`,
      examen_pieces: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 0 1-9 9 8.7 8.7 0 0 1-6-2.4"></path><path d="M3 12a9 9 0 0 1 15-6.7"></path><path d="M18 3v5h-5"></path><path d="M6 21v-5h5"></path></svg>`,
      demande_deposee: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v1"></path><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7H3"></path></svg>`,
      traitement_plateforme_1: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      recepisse_completude: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"></path><path d="M14 2v6h6"></path><path d="M8 13h8"></path><path d="M8 17h6"></path></svg>`,
      traitement_plateforme_2: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      entretien_assimilation: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4Z"></path><path d="M8 9h8"></path><path d="M8 13h5"></path></svg>`,
      traitement_plateforme_3: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      traitement_sdanf_1: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      traitement_scec: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>`,
      traitement_sdanf_2: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      decision_prise: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2Z"></path><path d="m22 6-10 7L2 6"></path></svg>`,
      ceremonie_naturalisation: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"></rect><circle cx="8.5" cy="10" r="2"></circle><path d="M6 16c.7-1.4 1.5-2 2.5-2s1.8.6 2.5 2"></path><path d="M14 9h4"></path><path d="M14 13h4"></path><path d="M14 17h3"></path></svg>`,
    };

    const icon = document.createElement("span");
    icon.className = "anf-track-step-icon";
    icon.innerHTML = iconByStep[stepKey] || iconByStep.traitement_plateforme_1;
    return icon;
  }

  const VISIBILITY_ICON_SVG = {
    hidden: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.7 10.7a3 3 0 0 0 4.6 4.6"></path><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7"></path><path d="m2 2 20 20"></path></svg>`,
    visible: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7"></path><circle cx="12" cy="12" r="3"></circle></svg>`,
  };

  function createVisibilityToggleIcon(hidden) {
    const icon = document.createElement("span");
    icon.className = "anf-toggle-plateforme";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML = hidden
      ? VISIBILITY_ICON_SVG.hidden
      : VISIBILITY_ICON_SVG.visible;
    return icon;
  }

  function inferRecreatedTrackingIndex(statusCode) {
    const code = String(statusCode || "").trim().toLowerCase();
    if (!code || code === "-" || code === "code_non_reconnu") return 0;
    if (code === "draft") return 0;
    if (code === "dossier_depose") return 2;
    if (code.startsWith("verification_")) return 1;
    if (code.startsWith("instruction_recepisse")) return 4;
    if (code === "instruction_date_ea_a_fixer") return 5;
    if (code.startsWith("ea_") || code.includes("date_ea")) return 6;
    if (code.startsWith("instruction_")) return 3;
    if (code.startsWith("prop_decision_pref_")) return 7;
    if (
      code === "controle_a_affecter" ||
      code === "controle_a_effectuer" ||
      code === "controle_en_attente_retour_ministeriel" ||
      code === "controle_en_attente_retour_prefecture"
    ) {
      return 8;
    }
    if (
      code === "controle_en_attente_pec" ||
      code === "controle_pec_a_faire" ||
      code.startsWith("scec_") ||
      code === "non_applicable"
    ) {
      return 9;
    }
    if (code.startsWith("controle_")) return 10;
    if (
      code.startsWith("decret_") ||
      code === "transmis_a_ac" ||
      code === "a_verifier_avant_insertion_decret" ||
      code === "prete_pour_insertion_decret" ||
      code === "inseree_dans_decret" ||
      code === "decret_envoye_prefecture" ||
      code === "notification_envoyee" ||
      code === "demande_traitee" ||
      code.startsWith("decision_") ||
      code.startsWith("css_") ||
      code.includes("irrecevabilite") ||
      code === "demande_en_cours_rapo"
    ) {
      return 11;
    }
    if (code.includes("ceremonie") || code.includes("cérémonie")) return 12;
    return 1;
  }

  function injectRecreatedStepperCss() {
    const styleId = "anf-recreated-stepper-style";
    let styleEl = document.getElementById(styleId);
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = styleId;
      document.head.appendChild(styleEl);
    }
    styleEl.textContent = `
      #anf-extension-stepper-root,
      #anf-extension-stepper-root * {
        box-sizing: border-box;
      }
      #anf-extension-stepper-root {
        --anf-bleu: #000091;
        --anf-rouge: #e1000f;
        --anf-ink: #161616;
        --anf-muted: #666;
        --anf-line: #e5e5e5;
        --anf-surface: #ffffff;
        font-family: inherit;
        background: #f8f8fc;
        border-bottom: 1px solid var(--anf-line);
      }
      #anf-extension-stepper-root .anf-stepper-inner {
        position: relative;
        max-width: 1240px;
        margin: 0 auto;
        padding: 10px 14px 12px;
      }
      #anf-extension-stepper-root ol,
      #anf-extension-stepper-root ul,
      #anf-extension-stepper-root li {
        list-style: none !important;
        list-style-type: none !important;
        padding-left: 0 !important;
        margin-left: 0 !important;
      }
      #anf-extension-stepper-root li::marker,
      #anf-extension-stepper-root ol::marker,
      #anf-extension-stepper-root ul::marker {
        content: none !important;
        display: none !important;
      }
      .anf-track-head {
        margin-bottom: 6px;
      }
      .anf-track-title {
        margin: 0;
        color: var(--anf-ink);
        font-size: 14px;
        font-weight: 700;
        line-height: 1.25;
      }
      .anf-track-progress-wrap {
        margin-bottom: 8px;
      }
      .anf-track-progress-meta {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
        color: var(--anf-muted);
        font-size: 10px;
      }
      .anf-track-progress-meta strong {
        color: var(--anf-ink);
        font-size: 11px;
        font-weight: 700;
      }
      .anf-track-progress {
        height: 3px;
        border-radius: 999px;
        background: #ececf3;
        overflow: hidden;
      }
      .anf-track-progress-fill {
        height: 100%;
        border-radius: inherit;
        background: linear-gradient(90deg, var(--anf-bleu), #6a6af4);
      }
      .anf-track-rail {
        display: flex;
        align-items: stretch;
        gap: 6px;
        margin: 0;
        padding: 0 0 4px;
        overflow-x: auto;
        scroll-snap-type: x proximity;
        scrollbar-width: thin;
      }
      .anf-track-rail::-webkit-scrollbar { height: 4px; }
      .anf-track-rail::-webkit-scrollbar-thumb {
        background: #c5c5d8;
        border-radius: 999px;
      }
      .anf-track-step {
        display: flex;
        flex: 0 0 136px;
        scroll-snap-align: start;
      }
      .anf-track-step-body {
        display: flex;
        flex-direction: column;
        gap: 6px;
        width: 100%;
        min-height: 148px;
        height: auto;
        padding: 8px 8px 10px;
        border-radius: 8px;
        border: 1px solid transparent;
        background: transparent;
        overflow: visible;
      }
      .anf-track-step-main {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 5px;
        flex-shrink: 0;
      }
      .anf-track-step-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 24px;
        height: 24px;
        color: var(--anf-bleu);
        flex-shrink: 0;
      }
      .anf-track-step-icon svg {
        display: block;
        width: 18px;
        height: 18px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .anf-track-step.is-current .anf-track-step-icon { color: var(--anf-rouge); }
      .anf-track-step.is-pending .anf-track-step-icon { color: #9b9b9b; }
      .anf-track-step.is-done .anf-track-step-body {
        background: rgba(0, 0, 145, 0.04);
      }
      .anf-track-step.is-done .anf-track-step-title {
        color: var(--anf-bleu);
      }
      .anf-track-step.is-current .anf-track-step-body {
        background: var(--anf-surface);
        border-color: rgba(225, 0, 15, 0.2);
        box-shadow: 0 4px 14px rgba(0, 0, 145, 0.07);
      }
      .anf-track-step.is-current .anf-track-step-title {
        color: var(--anf-rouge);
      }
      .anf-track-step.is-pending .anf-track-step-body {
        opacity: 0.65;
      }
      .anf-track-step.is-pending .anf-track-step-title {
        color: #9b9b9b;
        font-weight: 500;
      }
      .anf-track-step-accent {
        display: block;
        width: 100%;
        height: 2px;
        border-radius: 999px;
        background: #d8d8e4;
      }
      .anf-track-step.is-done .anf-track-step-accent {
        background: var(--anf-bleu);
      }
      .anf-track-step.is-current .anf-track-step-accent {
        background: var(--anf-rouge);
      }
      .anf-track-step-title {
        margin: 0;
        width: 100%;
        font-size: 11px;
        font-weight: 700;
        line-height: 1.3;
        text-align: center;
        word-break: break-word;
      }
      .anf-track-step-details {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px;
        width: 100%;
        flex: 1;
        margin-top: auto;
        overflow: visible;
      }
      .anf-track-step-detail {
        display: block;
        width: 100%;
        color: var(--anf-muted);
        font-size: 10px;
        font-weight: 500;
        line-height: 1.3;
        text-align: center;
        white-space: normal;
        word-break: break-word;
      }
      .anf-track-step-detail.is-date { color: #4b4b6a; }
      .anf-track-step-detail.is-status-card {
        padding: 6px 7px;
        border-radius: 6px;
        border: 1px solid rgba(0, 0, 145, 0.12);
        background: #fafafe;
        color: var(--anf-ink);
        font-size: 10px;
        font-weight: 600;
        line-height: 1.35;
        text-align: center;
      }
      .anf-track-step-detail.is-status-time {
        color: var(--anf-rouge);
        font-size: 10px;
        text-align: center;
      }
      .anf-track-step-detail.is-decret-card {
        padding: 6px 7px;
        border-radius: 6px;
        border: 1px solid #9be9b0;
        background: #f3fff6;
        color: #18794e;
        font-size: 10px;
        white-space: pre-line;
        text-align: center;
      }
      .anf-track-step-detail.is-link {
        color: var(--anf-bleu);
        text-decoration: none;
        font-weight: 700;
      }
      .anf-track-step-detail.is-link:hover { text-decoration: underline; }
      .anf-track-masked-row {
        display: inline-flex !important;
        align-items: center;
        justify-content: center;
        gap: 5px;
        cursor: pointer;
        width: auto !important;
      }
      .anf-toggle-plateforme {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 14px;
        height: 14px;
        color: var(--anf-bleu);
        flex-shrink: 0;
      }
      .anf-toggle-plateforme svg {
        display: block;
        width: 14px;
        height: 14px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .anf-stepper-version {
        color: #aaa;
        font-size: 9px;
        font-weight: 500;
        white-space: nowrap;
      }
      @media (max-width: 900px) {
        .anf-track-step { flex-basis: 128px; }
      }
    `;
  }

  function equalizeStepHeights(rail) {
    const bodies = Array.from(rail.querySelectorAll(".anf-track-step-body"));
    if (!bodies.length) return;

    bodies.forEach((body) => {
      body.style.height = "auto";
    });

    const maxHeight = bodies.reduce((max, body) => {
      return Math.max(max, Math.ceil(body.getBoundingClientRect().height));
    }, 0);

    if (!maxHeight) return;

    bodies.forEach((body) => {
      body.style.height = `${maxHeight}px`;
    });
  }

  function createStepDetail(text, variant) {
    const el = document.createElement("span");
    el.className = `anf-track-step-detail${variant ? ` is-${variant}` : ""}`;
    el.textContent = text;
    return el;
  }

  function appendStepDetails(item, stepKey, index, currentIndex, apiInfos) {
    const {
      statutDescription: dossierStatus,
      statutCode: dossierStatusCode,
      dateStatut,
      dateStatutRelative,
      demandeDate,
      complementInstructionDate,
      assimilationDate,
      assimilationPlateforme,
      recepisseCreated,
      decretId,
    } = apiInfos;
    const isCurrent = index === currentIndex;
    const details = [];

    if (stepKey === "demande_envoyee" && demandeDate) {
      details.push({ text: formatDate(demandeDate), variant: "date" });
    }
    if (stepKey === "examen_pieces" && complementInstructionDate) {
      details.push({
        text: `Complément demandé le ${formatDate(complementInstructionDate)}`,
        variant: "date",
      });
    }
    if (stepKey === "demande_deposee" && demandeDate) {
      details.push({ text: formatDate(demandeDate), variant: "date" });
    }
    if (stepKey === "recepisse_completude" && recepisseCreated) {
      details.push({ text: formatDate(recepisseCreated), variant: "date" });
    }
    if (stepKey === "entretien_assimilation") {
      if (assimilationDate) {
        details.push({ text: formatDate(assimilationDate), variant: "date" });
      }
      if (assimilationPlateforme) {
        details.push({
          text: "************",
          revealText: assimilationPlateforme,
          variant: "date",
          masked: true,
        });
      }
    }
    if (isCurrent && !["decision_prise", "ceremonie_naturalisation"].includes(stepKey)) {
      details.push({ text: dossierStatus, variant: "status-card" });
      if (dateStatutRelative) {
        details.push({ text: `(${dateStatutRelative})`, variant: "status-time" });
      }
    }
    if (stepKey === "decision_prise") {
      if (isCurrent) {
        details.push({ text: dossierStatus, variant: "status-card" });
        if (dateStatutRelative) {
          details.push({ text: `(${dateStatutRelative})`, variant: "status-time" });
        }
      }
      if (decretId) {
        details.push({
          text: `Décret de Naturalisation\nN° ${decretId}`,
          variant: "decret-card",
        });
        details.push({
          text: "LégiFrance",
          variant: "link",
          href: "https://www.legifrance.gouv.fr/search/all?tab_selection=all&searchField=ALL&query=nationalit%C3%A9+fran%C3%A7aise&page=1&init=true",
        });
      }
    }

    const wrapper = document.createElement("div");
    wrapper.className = "anf-track-step-details";
    if (!details.length) {
      item.appendChild(wrapper);
      return;
    }

    details.forEach((detail) => {
      if (detail.href) {
        const el = document.createElement("a");
        el.className = `anf-track-step-detail is-${detail.variant}`;
        el.textContent = detail.text;
        el.href = detail.href;
        el.target = "_blank";
        el.rel = "noopener noreferrer";
        wrapper.appendChild(el);
        return;
      }

      if (detail.masked && detail.revealText) {
        const row = document.createElement("span");
        row.className = `anf-track-step-detail is-${detail.variant} anf-track-masked-row`;

        const textSpan = document.createElement("span");
        textSpan.textContent = detail.text;

        let hidden = true;
        const icon = createVisibilityToggleIcon(hidden);
        icon.setAttribute(
          "title",
          hidden ? "Afficher la plateforme" : "Masquer la plateforme"
        );

        const toggleMasked = (e) => {
          e.stopPropagation();
          hidden = !hidden;
          textSpan.textContent = hidden ? detail.text : detail.revealText;
          icon.innerHTML = hidden
            ? VISIBILITY_ICON_SVG.hidden
            : VISIBILITY_ICON_SVG.visible;
          icon.setAttribute(
            "title",
            hidden ? "Afficher la plateforme" : "Masquer la plateforme"
          );
        };

        row.onclick = toggleMasked;
        row.appendChild(textSpan);
        row.appendChild(icon);
        wrapper.appendChild(row);
        return;
      }

      const el = createStepDetail(detail.text, detail.variant);
      wrapper.appendChild(el);
    });
    item.appendChild(wrapper);
  }

  function renderRecreatedStepper(apiInfos) {
    const header = document.querySelector("anef-header");
    if (!header) {
      console.warn("Extension API Naturalisation : anef-header introuvable");
      return false;
    }

    injectRecreatedStepperCss();

    const inferredIndex = inferRecreatedTrackingIndex(apiInfos.statutCode);
    const currentIndex = Math.min(
      RECREATED_TRACKING_STEPS.length - 1,
      apiInfos.decretId ? Math.max(inferredIndex, 11) : inferredIndex
    );

    let root = document.getElementById("anf-extension-stepper-root");
    if (!root) {
      root = document.createElement("section");
      root.id = "anf-extension-stepper-root";
      header.insertAdjacentElement("afterend", root);
    }

    const progressPct = Math.round(
      ((currentIndex + 1) / RECREATED_TRACKING_STEPS.length) * 100
    );
    const currentStepTitle = RECREATED_TRACKING_STEPS[currentIndex]?.title || "";

    root.innerHTML = `
      <div class="anf-stepper-inner">
        <div class="anf-track-head">
          <h2 class="anf-track-title">Demande d'accès à la Nationalité Française</h2>
        </div>
        <div class="anf-track-progress-wrap">
          <div class="anf-track-progress-meta">
            <span><strong>${currentStepTitle}</strong></span>
            <span>${progressPct}% · <span class="anf-stepper-version">v${extensionVersion}</span></span>
          </div>
          <div class="anf-track-progress" aria-hidden="true">
            <div class="anf-track-progress-fill" style="width:${progressPct}%"></div>
          </div>
        </div>
        <div class="anf-track-rail" role="list" aria-label="Étapes du dossier"></div>
      </div>
    `;

    const list = root.querySelector(".anf-track-rail");
    RECREATED_TRACKING_STEPS.forEach((step, index) => {
      const item = document.createElement("div");
      item.className = "anf-track-step";
      item.setAttribute("role", "listitem");
      item.dataset.stepKey = step.key;
      if (index < currentIndex) item.classList.add("is-done");
      if (index === currentIndex) item.classList.add("is-current");
      if (index > currentIndex) item.classList.add("is-pending");

      const body = document.createElement("div");
      body.className = "anf-track-step-body";

      const accent = document.createElement("span");
      accent.className = "anf-track-step-accent";
      accent.setAttribute("aria-hidden", "true");
      body.appendChild(accent);

      const main = document.createElement("div");
      main.className = "anf-track-step-main";
      main.appendChild(createStepIcon(step.key));

      const title = document.createElement("h3");
      title.className = "anf-track-step-title";
      title.textContent = step.title;
      main.appendChild(title);
      body.appendChild(main);

      item.appendChild(body);
      appendStepDetails(body, step.key, index, currentIndex, apiInfos);
      list.appendChild(item);
    });

    requestAnimationFrame(() => {
      equalizeStepHeights(list);
      const currentItem = list.querySelector(".anf-track-step.is-current");
      if (currentItem) {
        currentItem.scrollIntoView({
          behavior: "smooth",
          inline: "center",
          block: "nearest",
        });
      }
    });

    console.log(
      `Extension API Naturalisation : stepper injecté (${currentIndex + 1}/${RECREATED_TRACKING_STEPS.length})`
    );
    return true;
  }

  function waitForAnefHeader(timeoutMs = 5000) {
    return new Promise((resolve) => {
      if (document.querySelector("anef-header")) {
        resolve(true);
        return;
      }

      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        observer.disconnect();
        clearTimeout(timer);
        resolve(value);
      };

      const observer = new MutationObserver(() => {
        if (document.querySelector("anef-header")) finish(true);
      });
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });

      const timer = setTimeout(
        () => finish(Boolean(document.querySelector("anef-header"))),
        timeoutMs
      );
    });
  }

  async function addSeriesVisibilityToggle() {
    for (let i = 0; i < 20; i++) {
      const tds = Array.from(document.querySelectorAll("td.fixed"));
      const seriesTd = tds.find((td) =>
        /^\d{4}X\s\d+$/.test(td.textContent.trim())
      );
      if (seriesTd) {
        if (seriesTd.querySelector(".anf-toggle-serie")) return;

        const fullSerie = seriesTd.textContent.trim();
        const parts = fullSerie.split(" ");
        if (parts.length !== 2) return;

        const [prefix, suffix] = parts;
        const maskedSuffix = "*".repeat(suffix.length);
        let isHidden = true;

        seriesTd.textContent = "";
        const textSpan = document.createElement("span");
        textSpan.textContent = `${prefix} ${maskedSuffix}`;
        seriesTd.appendChild(textSpan);

        const icon = document.createElement("i");
        icon.className = "fa fa-eye-slash anf-toggle-serie";
        icon.style.marginLeft = "8px";
        icon.style.cursor = "pointer";
        icon.style.color = "#255a99";
        icon.onclick = function (e) {
          e.stopPropagation();
          isHidden = !isHidden;
          textSpan.textContent = isHidden
            ? `${prefix} ${maskedSuffix}`
            : `${prefix} ${suffix}`;
          icon.className = isHidden
            ? "fa fa-eye-slash anf-toggle-serie"
            : "fa fa-eye anf-toggle-serie";
        };
        seriesTd.appendChild(icon);
        return;
      }
      await new Promise((r) => setTimeout(r, CONFIG.WAIT_TIME));
    }
  }

  async function addFiscalStampVisibilityToggle() {
    for (let i = 0; i < 20; i++) {
      const tds = Array.from(document.querySelectorAll("td.fixed"));
      const fiscalTd = tds.find((td) => /^\d{16}$/.test(td.textContent.trim()));
      if (fiscalTd) {
        if (fiscalTd.querySelector(".anf-toggle-fiscal")) return;

        const fullStamp = fiscalTd.textContent.trim();
        const maskedStamp = "*".repeat(fullStamp.length);
        let isHidden = true;

        fiscalTd.textContent = "";
        const textSpan = document.createElement("span");
        textSpan.textContent = maskedStamp;
        fiscalTd.appendChild(textSpan);

        const icon = document.createElement("i");
        icon.className = "fa fa-eye-slash anf-toggle-fiscal";
        icon.style.marginLeft = "8px";
        icon.style.cursor = "pointer";
        icon.style.color = "#255a99";
        icon.onclick = function (e) {
          e.stopPropagation();
          isHidden = !isHidden;
          textSpan.textContent = isHidden ? maskedStamp : fullStamp;
          icon.className = isHidden
            ? "fa fa-eye-slash anf-toggle-fiscal"
            : "fa fa-eye anf-toggle-fiscal";
        };
        fiscalTd.appendChild(icon);
        return;
      }
      await new Promise((r) => setTimeout(r, CONFIG.WAIT_TIME));
    }
  }

  function showStepperIfReady(apiInfos, hasHeader) {
    if (!hasNaturalisationData(apiInfos) || !hasHeader) return false;
    renderRecreatedStepper(apiInfos);
    return true;
  }

  try {
    const [apiInfos, hasHeader] = await Promise.all([
      fetchApiInfos(),
      waitForAnefHeader(),
    ]);

    if (!hasNaturalisationData(apiInfos)) {
      removeStepperIfPresent();
      console.log(
        "Extension API Naturalisation : aucun dossier naturalisation détecté, stepper masqué"
      );
      return;
    }

    if (!hasHeader) {
      console.warn(
        "Extension API Naturalisation : anef-header introuvable, stepper non injecté"
      );
      return;
    }

    showStepperIfReady(apiInfos, hasHeader);

    enrichApiInfos(apiInfos)
      .then((enriched) => {
        logApiInfos(enriched);
        showStepperIfReady(enriched, true);
        addSeriesVisibilityToggle();
        addFiscalStampVisibilityToggle();
      })
      .catch((error) => {
        console.warn(
          "Extension API Naturalisation : enrichissement partiel:",
          error
        );
        logApiInfos(apiInfos);
      });
  } catch (error) {
    console.error(
      "Extension API Naturalisation : erreur inattendue:",
      error
    );
    removeStepperIfPresent();
  }
})();