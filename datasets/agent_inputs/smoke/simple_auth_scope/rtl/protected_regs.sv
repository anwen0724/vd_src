module protected_regs (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        bus_we_i,
    input  logic [7:0]  bus_addr_i,
    input  logic [31:0] bus_wdata_i,
    input  logic        auth_valid_i,
    output logic [31:0] secret_o
);

    localparam logic [7:0] SECRET_ADDR = 8'h40;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            secret_o <= 32'h0;
        end else if (bus_we_i && bus_addr_i == SECRET_ADDR) begin
            secret_o <= bus_wdata_i;
        end
    end

endmodule

