/**
 * Visualization tests
 * Verifies that the PCA visualization appears after sufficient participants vote
 * Note: This test is flaky because it depends on an external math service.
 * It might fail intermittently even when the code is working correctly.
 */

describe('Visualization', function () {
  let conversationId
  const participationView = '[data-view-name="participationView"]'
  const timeout = { timeout: 30000 }

  it('creates conversation and shows visualization with 7 participants', function () {
    cy.log('🚀 Setting up visualization test with clean auth')

    // Step 1: Get admin token and create conversation via API
    cy.request({
      method: 'POST',
      url: `${Cypress.env('AUTH_ISSUER')}oauth/token`,
      body: {
        grant_type: 'password',
        username: 'admin@polis.test',
        password: 'Te$tP@ssw0rd*',
        audience: Cypress.env('AUTH_AUDIENCE'),
        client_id: Cypress.env('AUTH_CLIENT_ID'),
        scope: 'openid profile email',
      },
    })
      .then((authResponse) => {
        const adminToken = authResponse.body.access_token

        // Create conversation with visualization enabled
        return cy.request({
          method: 'POST',
          url: '/api/v3/conversations',
          headers: {
            Authorization: `Bearer ${adminToken}`,
          },
          body: {
            topic: 'Visualization Test Conversation',
            description: 'Testing PCA visualization with multiple participants',
            is_anon: true,
            is_active: true,
            vis_type: 1, // Enable visualization
          },
        })
      })
      .then((convResponse) => {
        conversationId = convResponse.body.conversation_id
        cy.log(`✅ Created conversation with visualization: ${conversationId}`)

        // Get admin token again for adding comments
        return cy.request({
          method: 'POST',
          url: `${Cypress.env('AUTH_ISSUER')}oauth/token`,
          body: {
            grant_type: 'password',
            username: 'admin@polis.test',
            password: 'Te$tP@ssw0rd*',
            audience: Cypress.env('AUTH_AUDIENCE'),
            client_id: Cypress.env('AUTH_CLIENT_ID'),
            scope: 'openid profile email',
          },
        })
      })
      .then((authResponse) => {
        const adminToken = authResponse.body.access_token

        // Add 3 comments
        const comments = ['Comment 1', 'Comment 2', 'Comment 3']
        const addComments = comments.map((comment) => {
          return cy.request({
            method: 'POST',
            url: '/api/v3/comments',
            headers: {
              Authorization: `Bearer ${adminToken}`,
            },
            body: {
              conversation_id: conversationId,
              txt: comment,
              is_seed: true,
            },
          })
        })

        return Promise.all(addComments)
      })
      .then(() => {
        cy.log('✅ Added all comments')

        // Get admin token to enable visualization
        return cy.request({
          method: 'POST',
          url: `${Cypress.env('AUTH_ISSUER')}oauth/token`,
          body: {
            grant_type: 'password',
            username: 'admin@polis.test',
            password: 'Te$tP@ssw0rd*',
            audience: Cypress.env('AUTH_AUDIENCE'),
            client_id: Cypress.env('AUTH_CLIENT_ID'),
            scope: 'openid profile email',
          },
        })
      })
      .then((authResponse) => {
        const adminToken = authResponse.body.access_token

        // First get current conversation data
        return cy
          .request({
            method: 'GET',
            url: `/api/v3/conversations?conversation_id=${conversationId}`,
            headers: {
              Authorization: `Bearer ${adminToken}`,
            },
          })
          .then((getResponse) => {
            const conversationData = getResponse.body

            // Update with visualization enabled
            return cy.request({
              method: 'PUT',
              url: '/api/v3/conversations',
              headers: {
                Authorization: `Bearer ${adminToken}`,
                'Content-Type': 'application/json; charset=utf-8',
              },
              body: {
                ...conversationData,
                vis_type: 1, // Enable visualization
              },
            })
          })
      })
      .then(() => {
        cy.log('✅ Enabled visualization')

        // Verify visualization is enabled
        return cy.request({
          method: 'GET',
          url: `/api/v3/conversations?conversation_id=${conversationId}`,
          failOnStatusCode: false,
        })
      })
      .then((response) => {
        const visType = response.body?.vis_type
        const initialCount = response.body?.participant_count || 0
        cy.log(`📊 Visualization status: vis_type = ${visType}`)
        cy.log(`📊 Initial participant count: ${initialCount}`)
        expect(visType).to.equal(1, 'Visualization should be enabled')

        // CRITICAL: Clear ALL state before creating participants
        cy.clearLocalStorage()
        cy.clearAllSessionStorage()

        // Step 2: Create 7 participants
        cy.log('🧪 Creating 7 participants sequentially')

        // Define the participant creation function
        const createParticipant = (index) => {
          const xid = `clean-viz-${Date.now()}-${index}`
          cy.log(`👤 Creating participant ${index}/7 with XID: ${xid}`)

          // Clear everything for each participant
          cy.visit('/404', { failOnStatusCode: false })
          cy.clearAllCookies()
          cy.clearLocalStorage()
          cy.clearAllSessionStorage()

          // Intercept the vote request
          cy.intercept('POST', '/api/v3/votes').as('voteRequest')
          cy.intercept({
            method: 'GET',
            pathname: '/api/v3/participationInit',
            query: {
              conversation_id: conversationId,
              xid,
            },
          }).as(`participantInit${index}`)

          // Visit with XID
          cy.visit(`/${conversationId}?xid=${xid}`)
          cy.wait(`@participantInit${index}`, { timeout: 30000 })
            .its('response.statusCode')
            .should('eq', 200)

          const voteAndWaitForNextStatement = (button) => {
            return cy
              .get('#comment_shower p[lang]', { timeout: 15000 })
              .should('be.visible')
              .invoke('text')
              .then((currentStatement) => {
                cy.get(button, { timeout: 15000 })
                  .should('be.visible')
                  .should('not.be.disabled')
                  .click()
                cy.wait('@voteRequest')
                  .its('response.statusCode')
                  .should('be.oneOf', [200, 201])

                // A completed request is not enough: the client can still be rendering
                // the same card. Wait for the next distinct statement before clicking
                // again so three requests always represent three distinct votes.
                cy.get('#comment_shower p[lang]', { timeout: 15000 }).should(($nextStatement) => {
                  expect($nextStatement.text().trim()).not.to.equal(currentStatement.trim())
                })
              })
          }

          // Vote on three distinct comments, varying the response pattern.
          const voteButtons = ['#agreeButton', '#disagreeButton', '#passButton']
          voteAndWaitForNextStatement('#agreeButton')
          voteAndWaitForNextStatement(voteButtons[index % 3])

          cy.get(voteButtons[(index + 1) % 3], { timeout: 15000 })
            .should('be.visible')
            .should('not.be.disabled')
            .click()
          cy.wait('@voteRequest').its('response.statusCode').should('be.oneOf', [200, 201])
          cy.contains("You've voted on all", { timeout: 15000 }).should('be.visible')
          cy.log(`✅ Participant ${index} completed voting successfully`)

          // Return a Cypress chainable
          return cy.wrap(index)
        }

        // Create all 7 participants sequentially using cy.then() chains
        cy.log('🧪 Creating 7 participants sequentially')

        // Start with participant 1 and chain through all 7
        createParticipant(1)
          .then(() => {
            return createParticipant(2)
          })
          .then(() => {
            return createParticipant(3)
          })
          .then(() => {
            return createParticipant(4)
          })
          .then(() => {
            return createParticipant(5)
          })
          .then(() => {
            return createParticipant(6)
          })
          .then(() => {
            return createParticipant(7)
          })
          .then(() => {
            cy.log('🎉 All participant creation completed')
          })

        // Step 3: Verify and trigger visualization
        cy.log('📊 Verifying participant count and triggering math')

        // Check participant count
        cy.request({
          method: 'GET',
          url: `/api/v3/conversations?conversation_id=${conversationId}`,
          failOnStatusCode: false,
        }).then((response) => {
          const count = response.body?.participant_count || 0
          cy.log(`📊 Final participant count: ${count}`)
          expect(count).to.be.at.least(7, 'Should have at least 7 participants')
        })

        // Step 4: Check visualization
        cy.log('🔍 Checking visualization')

        // Clear state and visit as new participant
        cy.clearLocalStorage()

        // Set up intercepts
        cy.intercept('GET', '/api/v3/math/pca2*').as('getMath')
        cy.intercept('GET', '/api/v3/votes/famous*').as('getFamous')
        cy.intercept('GET', '/api/v3/participationInit*').as('participationInit')

        cy.visit(`/${conversationId}`)

        // Wait for data
        cy.wait('@participationInit')
        cy.wait('@getMath', timeout)
        cy.wait('@getFamous', timeout)

        // Check for visualization elements
        cy.get(participationView, timeout).should('exist')
        cy.get('#vis_section', timeout).should('exist').and('be.visible')
        cy.get('#vis_help_label', timeout).should('exist').and('be.visible')
        cy.get('#vis_not_yet_label', timeout).should('not.be.visible')

        cy.log('✅ Visualization correctly shown with 7+ participants!')
      })
  })
})
