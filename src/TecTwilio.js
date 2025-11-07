// TecTwilio.js
export const TecTwilio = {
  twimlResponse(twiml) {
    return new Response(twiml, {
      status: 200,
      headers: {
        'Content-Type': 'application/xml; charset=utf-8',
        'Cache-Control': 'no-store'
      }
    });
  },

  mainMenu() {
    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Gather numDigits="1"
          action="/twilio/handle-language"
          method="POST"
          timeout="5">
    <Say voice="Polly.Joanna" language="en-US">
      For English, press 1.
    </Say>
    <Say voice="Polly.Lupe" language="es-MX">
      Para español, oprima el dos.
    </Say>
  </Gather>

  <Say voice="Polly.Joanna" language="en-US">
    We didn't receive your selection. Please try again.
  </Say>
  <Redirect>/twilio/main-menu</Redirect>
</Response>`;
    return this.twimlResponse(twiml);
  },

  async handleLanguage(request) {
    const hotlineCallerId = '+19204322600';
    const englishVolunteer = '+19204713502';
    const spanishVolunteer = '+1XXXXXXXXXX'; // replace

    const raw = await request.text();
    const params = new URLSearchParams(raw);
    const digits = params.get('Digits') || '';

    if (digits === '1') {
      const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna" language="en-US">
    You have reached the Green Bay area Alcoholics Anonymous hotline.
    Following this message, this call will be forwarded to one of our hotline volunteers who are all members of A A.
    Our volunteers will be taking your call on their own personal phones and may just answer the phone with a simple hello.
    If they are unable to answer their phone, you will get their voicemail which may not specifically identify them as a hotline volunteer.
    Please do leave a message and your number and they will call you back as soon as they can.
    Thank you for calling the hotline, and please stay on the line while the call is forwarded.
  </Say>
  <Pause length="1" />
  <Dial callerId="${hotlineCallerId}" answerOnBridge="true" timeout="25">
    ${englishVolunteer}
  </Dial>
</Response>`;
      return this.twimlResponse(twiml);
    }

    if (digits === '2') {
      const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Lupe" language="es-MX">
    Ha llamado a la línea de ayuda de Alcohólicos Anónimos del área de Green Bay.
    Después de este mensaje, su llamada será transferida a uno de nuestros voluntarios, que todos son miembros de A A.
    Nuestros voluntarios contestan desde sus teléfonos personales y es posible que solo respondan con un simple hola.
    Si no pueden contestar, escuchará su buzón de voz, que puede que no se identifique específicamente como voluntario de la línea de ayuda.
    Por favor deje un mensaje con su número de teléfono y le devolverán la llamada tan pronto como puedan.
    Gracias por llamar a la línea de ayuda, y por favor permanezca en la línea mientras se transfiere la llamada.
  </Say>
  <Pause length="1" />
  <Dial callerId="${hotlineCallerId}" answerOnBridge="true" timeout="25">
    ${spanishVolunteer}
  </Dial>
</Response>`;
      return this.twimlResponse(twiml);
    }

    const invalid = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna" language="en-US">
    That was not a valid selection. Please try again.
  </Say>
  <Redirect>/twilio/main-menu</Redirect>
</Response>`;
    return this.twimlResponse(invalid);
  }
};
