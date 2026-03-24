describe("Query Search", () => {
  beforeEach(() => {
    cy.login();
  });

  it("finds a query by name via the search API", () => {
    cy.createQuery({ name: "Unique Searchable Query" }).then(() => {
      cy.request("GET", "/api/queries?q=Unique+Searchable").then(response => {
        expect(response.status).to.equal(200);
        expect(response.body.results.length).to.be.gte(1);
        const match = response.body.results.find(r => r.name.includes("Unique Searchable"));
        expect(match, "expected at least one result containing 'Unique Searchable'").to.not.be.undefined;
      });
    });
  });
});
